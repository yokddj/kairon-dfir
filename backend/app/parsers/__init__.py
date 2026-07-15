from app.parsers.base import ArtifactCandidate, ParsedRecord, ParserPlugin, ParserResult

# Import parser plugins so @register_parser decorators fire
import app.parsers.linux.triage  # noqa: F401
import app.parsers.windows.velociraptor  # noqa: F401
import app.parsers.windows.kape  # noqa: F401
import app.parsers.windows.evtx  # noqa: F401
import app.parsers.macos.triage  # noqa: F401
import app.parsers.network.pcap  # noqa: F401
import app.parsers.network.zeek  # noqa: F401
import app.parsers.rules.yara  # noqa: F401
import app.parsers.rules.sigma  # noqa: F401
import app.parsers.memory.volatility  # noqa: F401
import app.parsers.memory.memprocfs  # noqa: F401

