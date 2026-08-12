from app.ingest.raw_parsers.amcache_parser import AmcacheRawParser
from app.ingest.raw_parsers.evtx_parser import EvtxRawParser
from app.ingest.raw_parsers.lnk_parser import LnkRawParser
from app.ingest.raw_parsers.prefetch_parser import PrefetchRawParser
from app.ingest.raw_parsers.profile_list_parser import WindowsProfileListRawParser
from app.ingest.raw_parsers.sam_identity_parser import WindowsSamIdentityRawParser
from app.ingest.raw_parsers.service_parser import WindowsServiceRawParser
from app.ingest.raw_parsers.shimcache_parser import ShimcacheRawParser
from app.ingest.raw_parsers.system_hive_identity_parser import WindowsSystemHiveIdentityRawParser


def get_raw_parsers() -> list:
    return [
        EvtxRawParser(),
        LnkRawParser(),
        PrefetchRawParser(),
        AmcacheRawParser(),
        WindowsServiceRawParser(),
        ShimcacheRawParser(),
        WindowsSystemHiveIdentityRawParser(),
        WindowsSamIdentityRawParser(),
        WindowsProfileListRawParser(),
    ]
