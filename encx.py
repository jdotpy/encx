import struct
import json
import io

class EncryptionInterchangeFile():
    HEADER_TITLE = b'encx' 
    METADATA_ENCODING = 'utf-8'

    def __init__(self, metadata=None, payload=None):
        self.metadata = metadata
        self.payload = payload

    def _parse_header(self, stream):
        title_bytes = stream.read(len(self.HEADER_TITLE))
        if title_bytes != self.HEADER_TITLE:
            raise ValueError('File does not appear to be the right format')

        metadata_size_bytes = struct.unpack('<L', stream.read(4))[0]

        metadata_bytes = stream.read(metadata_size_bytes)
        json_metadata = metadata_bytes.decode(self.METADATA_ENCODING)
        return json.loads(json_metadata)

    def _create_header(self, stream, metadata):
        encoded_metadata = json.dumps(metadata).encode('utf-8')
        stream.write(self.HEADER_TITLE)
        stream.write(struct.pack('<L', len(encoded_metadata)))
        stream.write(encoded_metadata)
        return stream

    def to_file(self, path):
        with open(path, 'wb') as f:
            self._create_header(f, self.metadata)
            f.write(self.payload.read())

    def load_file(self, path):
        with open(path, 'rb') as f:
            self.metadata = self._parse_header(f)
            self.payload = io.BytesIO(f.read())

    @classmethod
    def from_file(cls, path):
        new_obj = cls()
        new_obj.load_file(path)
        return new_obj

ENCX = EncryptionInterchangeFile

def main():
    metadata = {'foo': 'bar', 'dataz': 42}
    with open('/dev/urandom', 'rb') as f:
        random_bytes = f.read(40)

    filename = 'foo.encx'

    print('Writing file...')
    ex = ENCX(metadata, io.BytesIO(random_bytes))
    ex.to_file(filename)
    print('...done!')

    print('Reading file...')
    reloaded = ENCX.from_file(filename)
    print('...done!')

    assert reloaded.metadata == metadata
    assert reloaded.payload.read() == random_bytes


if __name__ == '__main__':
    main()
