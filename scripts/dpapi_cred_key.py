import dpapick3.eater as eater

class DPAPICredKeyBlob(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwBlobSize = data.eat("L")
        self.dwField4 = data.eat("L")
        self.dwCredKeyOffset = data.eat("L")
        self.dwCredKeySize = data.eat("L")
        self.Guid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")
        assert data.ofs == self.dwCredKeyOffset
        self.CredKey = data.eat_string(self.dwCredKeySize)
