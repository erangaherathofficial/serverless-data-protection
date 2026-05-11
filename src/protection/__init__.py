"""Protection strategies package.

Importing this package loads each strategy submodule so their
``@register_protection`` decorators populate ``ProtectionRegistry`` at
package import time.
"""

from src.protection import aes256_encryption  # noqa: F401
from src.protection import masking  # noqa: F401
from src.protection import sha256_hashing  # noqa: F401
from src.protection import tokenization  # noqa: F401
