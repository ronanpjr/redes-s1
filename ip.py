from iputils import *
import struct
import ipaddress

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def _format_ipv4_header(self, dest_addr_str, src_addr_str, payload_len, ttl=64, proto=IPPROTO_TCP, identification=0, flags=0, frag_offset=0, dscp=0, ecn=0):
        vihl = (4 << 4) | 5
        dscpecn = (dscp << 2) | ecn
        total_length = 20 + payload_len
        flags_frag = (flags << 13) | frag_offset
        checksum = 0 
        header_without_checksum = struct.pack('!BBHHHBBH',
                                 vihl, dscpecn, total_length,
                                 identification, flags_frag, ttl, proto,
                                 checksum, 
                                 ) + str2addr(src_addr_str) + str2addr(dest_addr_str)
        actual_checksum = calc_checksum(header_without_checksum)
        header_with_checksum = struct.pack('!BBHHHBBH',
                                 vihl, dscpecn, total_length,
                                 identification, flags_frag, ttl, proto,
                                 actual_checksum,
                                 ) + str2addr(src_addr_str) + str2addr(dest_addr_str)
        return header_with_checksum

    def __raw_recv(self, datagrama):
        if len(datagrama) < 20:
            return 

        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else: 
            new_ttl = ttl - 1

            if new_ttl <= 0:
                if self.meu_endereco:
                    icmp_type = 11
                    icmp_code = 0
                    icmp_checksum_placeholder = 0
                    ihl_bytes_original = (datagrama[0] & 0x0F) * 4
                    icmp_error_payload_data = datagrama[:ihl_bytes_original + 8]
                    icmp_header_no_checksum = struct.pack('!BBH', icmp_type, icmp_code, icmp_checksum_placeholder) + b'\x00\x00\x00\x00'
                    icmp_segment_for_checksum = icmp_header_no_checksum + icmp_error_payload_data
                    actual_icmp_checksum = calc_checksum(icmp_segment_for_checksum)
                    icmp_header_with_checksum = struct.pack('!BBH', icmp_type, icmp_code, actual_icmp_checksum) + b'\x00\x00\x00\x00'
                    icmp_full_payload = icmp_header_with_checksum + icmp_error_payload_data
                    ip_header_for_icmp = self._format_ipv4_header(
                        dest_addr_str=src_addr, 
                        src_addr_str=self.meu_endereco,
                        payload_len=len(icmp_full_payload),
                        ttl=64, proto=IPPROTO_ICMP, identification=0, 
                        dscp=0, ecn=0, flags=0, frag_offset=0)
                    icmp_datagram_to_send = ip_header_for_icmp + icmp_full_payload
                    next_hop_for_icmp = self._next_hop(src_addr)
                    if next_hop_for_icmp:
                        self.enlace.enviar(icmp_datagram_to_send, next_hop_for_icmp)
                return 
            next_hop_ip_str = self._next_hop(dst_addr)
            ihl_bytes = (datagrama[0] & 0x0F) * 4
            new_header_bytearray = bytearray(datagrama[:ihl_bytes])
            new_header_bytearray[8] = new_ttl
            new_header_bytearray[10:12] = b'\x00\x00'
            new_checksum = calc_checksum(bytes(new_header_bytearray))
            new_header_bytearray[10:12] = struct.pack('!H', new_checksum)
            forwarded_datagrama = bytes(new_header_bytearray) + payload
            
            self.enlace.enviar(forwarded_datagrama, next_hop_ip_str)

    def _next_hop(self, dest_addr_str):
        if not self.tabela_encaminhamento:
            return None
        try:
            dest_addr_ip_obj = ipaddress.ip_address(dest_addr_str)
        except ValueError: 
            return None

        for network_obj, _prefix_len, next_hop_ip in self.tabela_encaminhamento:
            if dest_addr_ip_obj in network_obj:
                return next_hop_ip
        return None

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = []
        if tabela is None: 
            return
        for cidr_str, next_hop_ip_str in tabela:
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                self.tabela_encaminhamento.append((network, network.prefixlen, next_hop_ip_str))
            except ValueError:
                pass 
        self.tabela_encaminhamento.sort(key=lambda item: item[1], reverse=True)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr_str):
        if self.meu_endereco is None:
            return
        next_hop_ip_str = self._next_hop(dest_addr_str)
        if next_hop_ip_str is None:
            return

        payload_len = len(segmento)
        datagrama_to_send_header = self._format_ipv4_header(
            dest_addr_str=dest_addr_str,
            src_addr_str=self.meu_endereco,
            payload_len=payload_len,
            ttl=64, proto=IPPROTO_TCP, identification=0)
        full_datagrama_to_send = datagrama_to_send_header + segmento
        self.enlace.enviar(full_datagrama_to_send, next_hop_ip_str)