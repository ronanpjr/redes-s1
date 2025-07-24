class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        self.enlaces = {}
        self.callback = None
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.buffer = b''

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        datagrama_escaped = datagrama.replace(b'\xdb', b'\xdb\xdd')
        datagrama_escaped = datagrama_escaped.replace(b'\xc0', b'\xdb\xdc')
        quadro = b'\xc0' + datagrama_escaped + b'\xc0'
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        self.buffer += dados
        quadros = self.buffer.split(b'\xc0')
        self.buffer = quadros[-1]
        for quadro in quadros[:-1]:
            if not quadro:
                continue
            try:
                datagrama = quadro.replace(b'\xdb\xdc', b'\xc0')
                datagrama = datagrama.replace(b'\xdb\xdd', b'\xdb')
                self.callback(datagrama)
            except:
                import traceback
                traceback.print_exc()