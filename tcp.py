import asyncio
import random
import time
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port) 

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            if id_conexao not in self.conexoes or self.conexoes[id_conexao].connection_state == "CLOSED":
                conexao = Conexao(self, id_conexao, seq_no) 
                self.conexoes[id_conexao] = conexao
                if self.callback:
                    self.callback(conexao)
        elif id_conexao in self.conexoes:
            if self.conexoes[id_conexao].connection_state != "CLOSED":
                 self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            pass


class Conexao:
    def __init__(self, servidor, id_conexao, client_isn):
        self.servidor = servidor
        self.id_conexao = id_conexao 
        self.client_addr, self.client_port, self.servidor_addr, self.servidor_port = id_conexao
        self.callback = None 
        self.server_isn = random.randint(0, 0xffff)
        self.seq_no_envio = self.server_isn
        self.expected_seq_no = client_isn + 1
        ack_para_cliente_syn = client_isn + 1 
        header_syn_ack = make_header(self.servidor_port, self.client_port, self.seq_no_envio, ack_para_cliente_syn, FLAGS_SYN | FLAGS_ACK)
        segmento_syn_ack = fix_checksum(header_syn_ack, self.servidor_addr, self.client_addr)
        self.servidor.rede.enviar(segmento_syn_ack, self.client_addr)
        self.seq_no_envio += 1
        self.send_base = self.seq_no_envio 
        self.send_buffer = b'' 
        self.unacked_segments = []  
        self.timer = None
        self.timeout_interval = 1.0  
        self.estimated_rtt = None
        self.dev_rtt = None
        self._RTT_ALPHA = 0.125 
        self._RTT_BETA = 0.25   
        self._RTT_K = 4         
        self.cwnd = MSS  
        self.bytes_acked_for_cwnd_increase = 0 
        self.current_cwnd_target_for_increase = self.cwnd 
        self.connection_state = "ESTABLISHED" 
        self.fin_received_from_client = False
        self.fin_sent_by_server = False    
        self.client_fin_seq_no = -1     

    def _start_timer(self):
        if self.timer: 
            self.timer.cancel()
            self.timer = None
        if not self.unacked_segments: 
            return
        
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._handle_timeout)

    def _stop_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _handle_timeout(self):
        self.timer = None 
        if not self.unacked_segments or self.connection_state == "CLOSED":
            return

        segment_info = self.unacked_segments[0]
        self.servidor.rede.enviar(segment_info['segment'], self.client_addr)
        segment_info['transmissions'] += 1
        current_cwnd_in_mss = self.cwnd // MSS 
        new_cwnd_in_mss = max(1, current_cwnd_in_mss // 2) 
        self.cwnd = new_cwnd_in_mss * MSS 
        self.bytes_acked_for_cwnd_increase = 0 
        self.current_cwnd_target_for_increase = self.cwnd 
        self._start_timer() 

    def _update_rtt_and_timeout(self, sample_rtt):
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2.0
        else:
            self.estimated_rtt = (1 - self._RTT_ALPHA) * self.estimated_rtt + self._RTT_ALPHA * sample_rtt
            self.dev_rtt = (1 - self._RTT_BETA) * self.dev_rtt + self._RTT_BETA * abs(sample_rtt - self.estimated_rtt)
        
        rto = self.estimated_rtt + self._RTT_K * self.dev_rtt
        self.timeout_interval = max(rto, 0.2) 

    def _process_ack(self, ack_no):
        progress_made = False
        if ack_no > self.send_base: 
            newly_acked_length_total = 0
            new_unacked_list = []
            for seg_info in self.unacked_segments:
                if seg_info['ack_expected'] <= ack_no: 
                    newly_acked_length_total += seg_info['len']
                    if seg_info['transmissions'] == 1 and seg_info['time_sent'] is not None:
                        sample_rtt = time.time() - seg_info['time_sent']
                        self._update_rtt_and_timeout(sample_rtt)
                else:
                    new_unacked_list.append(seg_info)
            
            if newly_acked_length_total > 0:
                progress_made = True

            self.unacked_segments = new_unacked_list
            self.send_base = ack_no 

            if newly_acked_length_total > 0: 
              
                self.bytes_acked_for_cwnd_increase += newly_acked_length_total
                
                
                if self.bytes_acked_for_cwnd_increase >= self.current_cwnd_target_for_increase and \
                   self.current_cwnd_target_for_increase > 0:
                                        
                    self.cwnd += MSS
                    self.bytes_acked_for_cwnd_increase = 0 
                
            if self.unacked_segments:
                self._start_timer() 
            else:
                self._stop_timer()

        if self.fin_sent_by_server and ack_no == self.seq_no_envio: 
            progress_made = True 
            if self.connection_state == "FIN_WAIT_1":
                self.connection_state = "FIN_WAIT_2"
            elif self.connection_state == "LAST_ACK":
                self.connection_state = "CLOSED"
                self._cleanup_connection()
            elif self.connection_state == "CLOSING": 
                 self.connection_state = "TIME_WAIT" 
                 self.connection_state = "CLOSED"; self._cleanup_connection()
        
        return progress_made


    def _process_fin(self, seq_no):
        fin_is_newly_processed = False
        if (not self.fin_received_from_client and seq_no == self.expected_seq_no) or \
           (self.fin_received_from_client and seq_no == self.client_fin_seq_no and seq_no >= self.expected_seq_no -1 ):

            if not self.fin_received_from_client: 
                self.fin_received_from_client = True
                self.client_fin_seq_no = seq_no 
                self.expected_seq_no += 1      
                if self.callback:
                    self.callback(self, b'')
                fin_is_newly_processed = True
            
            ack_for_client_fin = self.client_fin_seq_no + 1
            ack_header = make_header(self.servidor_port, self.client_port, self.seq_no_envio, ack_for_client_fin, FLAGS_ACK)
            ack_segment = fix_checksum(ack_header, self.servidor_addr, self.client_addr)
            self.servidor.rede.enviar(ack_segment, self.client_addr)

            if fin_is_newly_processed: 
                if self.connection_state == "ESTABLISHED":
                    self.connection_state = "CLOSE_WAIT"
                elif self.connection_state == "FIN_WAIT_1": 
                    self.connection_state = "CLOSING"
                elif self.connection_state == "FIN_WAIT_2": 
                    self.connection_state = "TIME_WAIT" 
                    self.connection_state = "CLOSED"; self._cleanup_connection() 
        return fin_is_newly_processed

    def _process_data(self, seq_no, payload):
        ack_sent_for_data = False
        if not payload: return ack_sent_for_data

        if self.connection_state not in ["ESTABLISHED", "CLOSE_WAIT"]:
            return ack_sent_for_data 

        if seq_no == self.expected_seq_no:
            self.expected_seq_no += len(payload)
            if self.callback:
                self.callback(self, payload)
            
            ack_header = make_header(self.servidor_port, self.client_port, self.seq_no_envio, self.expected_seq_no, FLAGS_ACK)
            ack_segment = fix_checksum(ack_header, self.servidor_addr, self.client_addr)
            self.servidor.rede.enviar(ack_segment, self.client_addr)
            ack_sent_for_data = True
        elif seq_no < self.expected_seq_no: 
            ack_header = make_header(self.servidor_port, self.client_port, self.seq_no_envio, self.expected_seq_no, FLAGS_ACK)
            ack_segment = fix_checksum(ack_header, self.servidor_addr, self.client_addr)
            self.servidor.rede.enviar(ack_segment, self.client_addr)
            ack_sent_for_data = True 
        else: 
            ack_header = make_header(self.servidor_port, self.client_port, self.seq_no_envio, self.expected_seq_no, FLAGS_ACK)
            ack_segment = fix_checksum(ack_header, self.servidor_addr, self.client_addr)
            self.servidor.rede.enviar(ack_segment, self.client_addr)
            ack_sent_for_data = True
        return ack_sent_for_data


    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
    
        if self.connection_state == "CLOSED":
            return

        acked_progress = False
        
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            acked_progress = self._process_ack(ack_no)
            if self.connection_state == "CLOSED":
                return 

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self._process_fin(seq_no) 
            if self.connection_state == "CLOSED":
                return 

        if payload: 
            self._process_data(seq_no, payload)
        
        if acked_progress and len(self.send_buffer) > 0: 
            self._attempt_send_data()


    def registrar_recebedor(self, callback):
        self.callback = callback

    def _attempt_send_data(self):
        if self.connection_state not in ["ESTABLISHED", "CLOSE_WAIT"]:
            return

        initial_fila_len = -1
        if hasattr(self.servidor.rede, 'fila') and isinstance(self.servidor.rede.fila, list):
            initial_fila_len = len(self.servidor.rede.fila)
        
        segments_actually_sent_this_invocation = 0 

        while len(self.send_buffer) > 0:
            current_flight_size = 0
            for seg_info_fs in self.unacked_segments:
                current_flight_size += seg_info_fs['len']
            
            allowed_to_send_this_time = self.cwnd - current_flight_size
            
            if allowed_to_send_this_time <= 0:
                break 

            chunk_size = min(MSS, len(self.send_buffer), allowed_to_send_this_time)
            if chunk_size <= 0: 
                break

            payload_chunk = self.send_buffer[:chunk_size]
            current_payload_seq_no = self.seq_no_envio 
            
            header = make_header(self.servidor_port, self.client_port, current_payload_seq_no, self.expected_seq_no, FLAGS_ACK)
            segmento_bytes = header + payload_chunk
            segmento_com_checksum = fix_checksum(segmento_bytes, self.servidor_addr, self.client_addr)
          
            self.servidor.rede.enviar(segmento_com_checksum, self.client_addr)
                        
            segments_actually_sent_this_invocation += 1 
            
            self.send_buffer = self.send_buffer[chunk_size:] 
            self.seq_no_envio += len(payload_chunk)         
            
            seg_info_to_send = { 
                'seq': current_payload_seq_no, 
                'len': len(payload_chunk),
                'ack_expected': current_payload_seq_no + len(payload_chunk),
                'segment': segmento_com_checksum,
                'time_sent': time.time(), 
                'transmissions': 1
            }
            self.unacked_segments.append(seg_info_to_send)

            if self.timer is None and self.unacked_segments: 
                self._start_timer()

        final_fila_len = -1
        if hasattr(self.servidor.rede, 'fila') and isinstance(self.servidor.rede.fila, list):
            final_fila_len = len(self.servidor.rede.fila)

    def enviar(self, dados):
        if self.connection_state not in ["ESTABLISHED", "CLOSE_WAIT"]:
            return
        if not dados: 
            return

        self.send_buffer += dados
        self._attempt_send_data() 
        
    def fechar(self):
        if self.connection_state in ["ESTABLISHED", "CLOSE_WAIT"]:
            if not self.fin_sent_by_server : 
                self.fin_sent_by_server = True
                fin_seq_to_use = self.seq_no_envio 

                header_fin = make_header(self.servidor_port, self.client_port, fin_seq_to_use, self.expected_seq_no, FLAGS_FIN | FLAGS_ACK)
                segmento_fin = fix_checksum(header_fin, self.servidor_addr, self.client_addr)
                
                self.servidor.rede.enviar(segmento_fin, self.client_addr)
                self.seq_no_envio += 1 

                if self.connection_state == "ESTABLISHED":
                    self.connection_state = "FIN_WAIT_1"
                elif self.connection_state == "CLOSE_WAIT": 
                    self.connection_state = "LAST_ACK"
        
        elif self.connection_state == "CLOSED":
            pass

    def _cleanup_connection(self):
        self._stop_timer()
        self.connection_state = "CLOSED" 
        if self.id_conexao in self.servidor.conexoes:
             if self.servidor.conexoes[self.id_conexao] is self: 
                del self.servidor.conexoes[self.id_conexao]