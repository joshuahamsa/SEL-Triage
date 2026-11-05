"""Fixed, read-only command policy for supported SEL device families."""

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class SelCommand:
    """One library-owned command that is safe at SEL Access Level 1."""

    capability: str
    wire_text: str
    terminal_prompt: bytes
    max_bytes: int
    max_seconds: float = 30.0
    integer_argument: bool = False
    filename_argument: bool = False

    def render(self, argument: object = None) -> str:
        """Render only the recipe's validated integer or settings-file argument, if any."""

        if self.filename_argument:
            if type(argument) is not str or not SETTINGS_FILENAME.fullmatch(argument):
                raise ValueError(
                    "{0} requires a settings file name (CFG.TXT or SET_<class>.TXT)".format(
                        self.capability
                    )
                )
            return "{0} {1}".format(self.wire_text, argument)
        if self.integer_argument:
            if type(argument) is not int or argument < 1:
                raise ValueError(
                    "{0} requires a positive integer argument".format(
                        self.capability
                    )
                )
            return "{0} {1}".format(self.wire_text, argument)
        if argument is not None:
            raise ValueError(
                "{0} does not accept an argument".format(self.capability)
            )
        return self.wire_text


# The only files FILE READ / FILE SHOW may name: the settings class list and the
# settings streams it lists (SET_1.TXT, set_G.txt, SET_HMI.TXT, ...). Case is kept as
# given; the device ignores it.
SETTINGS_FILENAME = re.compile(r"(?:CFG|SET_[A-Z0-9]{1,8})\.TXT", re.IGNORECASE)


def _command(
    capability: str,
    wire_text: str,
    max_bytes: int,
    max_seconds: float = 30.0,
    integer_argument: bool = False,
    filename_argument: bool = False,
) -> SelCommand:
    return SelCommand(
        capability,
        wire_text,
        b"=>",
        max_bytes,
        max_seconds,
        integer_argument,
        filename_argument,
    )


_IDENTITY = _command("identity", "ID", 64 * 1024)
# HELP, not HLP: live SEL-751 and SEL-735 firmware reject "HLP" (the 751 says
# 'Enter "HELP"'); HELP lists the commands available at the current access level.
_HELP = _command("help", "HELP", 128 * 1024)
_STATUS = _command("status", "STA", 128 * 1024)
_METER = _command("meter", "MET", 128 * 1024)
_BREAKER = _command("breaker", "BRE", 128 * 1024)
_HISTORY = _command("history", "HIS", 256 * 1024)
_TARGET = _command("target", "TAR", 128 * 1024)
_SER = _command("ser", "SER", 1024 * 1024, max_seconds=60.0)
_EVE = _command(
    "eve", "EVE", 1024 * 1024, max_seconds=60.0, integer_argument=True
)
_CEV = _command(
    "cev", "CEV", 1024 * 1024, max_seconds=60.0, integer_argument=True
)
_CEV_RAW = _command(
    "cev_raw", "CEV R", 1024 * 1024, max_seconds=60.0, integer_argument=True
)
# SHO only displays settings; Access Level 1 cannot change them. Without a
# group number, SHO and SHO L report the active group.
_SETTINGS_GLOBAL = _command(
    "settings_global", "SHO G", 256 * 1024, max_seconds=60.0
)
_SETTINGS_GROUP = _command("settings_group", "SHO", 256 * 1024, max_seconds=60.0)
_SETTINGS_LOGIC = _command(
    "settings_logic", "SHO L", 256 * 1024, max_seconds=60.0
)
_SETTINGS_REPORT = _command(
    "settings_report", "SHO R", 256 * 1024, max_seconds=60.0
)
# FILE READ / FILE SHOW copy a settings file *from* the device (Access Level 1
# cannot change settings). FILE READ answers with an XMODEM/YMODEM transfer that
# SelClient.read_file drives; FILE SHOW prints the file as framed text (used for
# the SEL-735, whose XMODEM sender gives up before a cross-network handshake).
_FILE_READ = _command(
    "file_read", "FILE READ", 2 * 1024 * 1024, max_seconds=120.0,
    filename_argument=True,
)
_FILE_SHOW = _command(
    "file_show", "FILE SHOW", 2 * 1024 * 1024, max_seconds=120.0,
    filename_argument=True,
)
_FILE_COMMANDS = {"file_read": _FILE_READ, "file_show": _FILE_SHOW}


def _build_command_policy() -> Mapping[str, Mapping[str, SelCommand]]:
    commands_by_family = {
        # The conservative generic surface is sufficient to identify an unknown
        # relay without probing it with model-specific commands.
        "generic": {
            "identity": _IDENTITY,
            "help": _HELP,
        },
        "sel700g": {
            "identity": _IDENTITY,
            "help": _HELP,
            "status": _STATUS,
            "meter": _METER,
            "breaker": _BREAKER,
            "history": _HISTORY,
            "target": _TARGET,
            "eve": _EVE,
            "cev": _CEV,
            "ser": _SER,
            "settings_global": _SETTINGS_GLOBAL,
            "settings_group": _SETTINGS_GROUP,
            "settings_logic": _SETTINGS_LOGIC,
            "settings_report": _SETTINGS_REPORT,
        },
        "sel751": {
            "identity": _IDENTITY,
            "help": _HELP,
            "status": _STATUS,
            "meter": _METER,
            "breaker": _BREAKER,
            "history": _HISTORY,
            "target": _TARGET,
            # SER and EVE are Level 1 reads used by sel-event-sweep; adapter
            # capabilities are unchanged so snapshots do not run them.
            "eve": _EVE,
            "ser": _SER,
        },
        # SEL-851: BRE is not a recognized command.
        "sel851": {
            "identity": _IDENTITY,
            "help": _HELP,
            "status": _STATUS,
            "meter": _METER,
            "history": _HISTORY,
            "target": _TARGET,
            # SER and EVE are Level 1 reads used by sel-event-sweep; adapter
            # capabilities are unchanged so snapshots do not run them.
            "eve": _EVE,
            "ser": _SER,
        },
        "sel351": {
            "identity": _IDENTITY,
            "help": _HELP,
            "status": _STATUS,
            "meter": _METER,
            "breaker": _BREAKER,
            "history": _HISTORY,
            "target": _TARGET,
            # SER and EVE are Level 1 reads used by sel-event-sweep; adapter
            # capabilities are unchanged so snapshots do not run them.
            "eve": _EVE,
            "ser": _SER,
        },
        # SEL-735 meters: no breaker monitor.
        "sel735": {
            "identity": _IDENTITY,
            "help": _HELP,
            "status": _STATUS,
            "meter": _METER,
            "history": _HISTORY,
            "target": _TARGET,
            # SER and EVE are Level 1 reads used by sel-event-sweep; adapter
            # capabilities are unchanged so snapshots do not run them.
            "eve": _EVE,
            "ser": _SER,
        },
        "sel651": {
            "identity": _IDENTITY,
            "status": _STATUS,
            "meter": _METER,
            "history": _HISTORY,
            "eve": _EVE,
            "cev": _CEV,
            "cev_raw": _CEV_RAW,
            "ser": _SER,
        },
    }
    # Settings capture runs on every family, unknown SEL models included.
    for commands in commands_by_family.values():
        commands.update(_FILE_COMMANDS)
    return MappingProxyType(
        {
            family: MappingProxyType(commands)
            for family, commands in commands_by_family.items()
        }
    )


COMMANDS_BY_FAMILY: Mapping[str, Mapping[str, SelCommand]] = (
    _build_command_policy()
)


__all__ = ["COMMANDS_BY_FAMILY", "SETTINGS_FILENAME", "SelCommand"]
