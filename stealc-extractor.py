"""
StealC Configuration extractor
Matthew @embee_research

Samples:
03833086b4705d343f299c1639db1a242cd508d4f118d55ca427cb1c5517b589
038a54d0e765a4c93175d4e61a4c76fb9267d5120fdfa0f634e5bfdbcdc58529
0873b7a5cfae17a6dfebe6afde535a186b08d76b4b8ef56a129459c56f016729
11a4d950c18b1e65c593d5ae5f5f26b9f4fdd24adb0063bb53dd2dc2564c94ac
1565a0a1cf2ad6c0dacb650fff7b178acd2a4107bfe120873b00109dbc248877

"""


import base64
import os
import re
from Crypto.Cipher import ARC4

from maco.extractor import Extractor
from maco.model import ExtractorModel, ConnUsageEnum
from sys import argv
from typing import BinaryIO, List, Optional


class Stealc(Extractor):
    family = "Stealc"
    author = "@embee_research"
    last_modified = "2024-01-21"
    sharing: str = "TLP:CLEAR"
    yara_rule: str = open(os.path.join(os.path.dirname(__file__), 'win_stealc_bytecodes_oct_2023.yar'), 'r').read()

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        content = stream.read()
        cfg = ExtractorModel(family=self.family)

        # Search for hex-like rc4 key
        key_pattern = re.compile(b"[a-f0-9]{15,30}")
        key_results = key_pattern.findall(content)

        # Search for rc4 + base64 encoded data
        config_patterns = re.compile(b"[a-zA-Z0-9\=\+\/]{10,}")
        config_results = config_patterns.findall(content)


        key = key_results[0]
        final = []

        # go through base64 list and attempt to rc4 decrypt
        cipher = ARC4.new(key)
        for result in config_results:
            try:
                cipher = ARC4.new(key)
                result = base64.b64decode(result.decode('utf-8'))
                msg = cipher.decrypt(result)
                out = msg
                final.append(out)

            except Exception as e:
                # self.logger.error(e)
                pass

        # look for patterns that indicate a c2 or url
        for i in final:
            if b":/" in i or len(str(i).split(".")) > 3:
                c2_url = i.decode('utf-8')
                self.logger.info(c2_url)
                cfg.http.append(cfg.Http(uri=c2_url, usage=ConnUsageEnum.c2))

        return cfg


if __name__ == "__main__":
    import yara
    parser = Stealc()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f, matches=yara.compile(source=parser.yara_rule).match(file_path))
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
