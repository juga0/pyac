
import os.path


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# NOTE: key size is 3072 for Level 1
KEY_SIZE = 3072

NOPREFERENCE = 'nopreference'
MUTUAL = 'mutual'

AC = 'Autocrypt'
ADDR = 'addr'
KEYDATA = 'keydata'
PE = 'prefer-encrypt'

PE_HEADER_TYPES = [None, NOPREFERENCE, MUTUAL]

AC_HEADER_PE = "addr=%(addr)s; prefer-encrypt=%(pe)s; keydata=%(keydata)s"
AC_HEADER = "addr=%(addr)s; keydata=%(keydata)s"

AC_GOSSIP = 'Autocrypt-Gossip'
AC_GOSSIP_HEADER = "addr=%(addr)s; keydata=%(keydata)s"

RESET = 'reset'
GOSSIP = 'gossip'

ACCOUNTS = 'accounts'
PEERS = 'peers'

SECKEY = 'seckey'
PUBKEY = 'pubkey'
PREFER_ENCRYPT = 'prefer_encrypt'
PREFERENCRYPT = 'preferencrypt'

ACCOUNT_PE_TYPES = [NOPREFERENCE, MUTUAL]

LASTSEEN = 'lastseen'
ACTIMESTAMP = 'actimestamp'
GOSSIPKEY = 'gossipkey'
GOSSIPTS = 'gossiptimestamp'


PEER_STATE_TYPES = [NOPREFERENCE, MUTUAL, RESET, GOSSIP]

CERTIFICATE = 'certificate'

RECOMMENDATION = 'recommendation'

DISABLE = 'disable'
DISCOURAGE = 'discourage'
AVAILABE = 'available'
ENCRYPT = 'encrypt'

AC_PREFER_ENCRYPT_HEADER = 'Autocrypt-Prefer-Encrypt: '
AC_SETUP_MSG = "Autocrypt-Setup-Message"
AC_SETUP_MSG_KEY = 'Autocrypt-Setup-Message: '
LEVEL_NUMBER = 'v1'
AC_SETUP_MSG_HEADER = AC_SETUP_MSG + LEVEL_NUMBER
AC_CT_SETUP = 'autocrypt-setup'
# AC_CT_SETUP = 'autocrypt-setup; filename="autocrypt-setup-message.txt"
# NOTE: attachment will add HTML text with email library, so using .html ext.
AC_CT_SETUP_FN = "autocrypt-setup-message.html"

AC_SETUP_TEXT = """This message contains all information to transfer your Autocrypt
settings along with your secret key securely from your original
device.

To set up your new device for Autocrypt, please follow the
instuctions that should be presented by your new device.

You can keep this message and use it as a backup for your secret
key. If you want to do this, you should write down the Setup Code
and store it securely.
"""

AC_SETUP_INTRO = """This is the Autocrypt setup file used to transfer settings and
keys between clients. You can decrypt it using the Setup Code
presented on your old device, and then import the contained key
into your keyring.
"""

AC_SETUP_SUBJECT = """Autocrypt Setup Message"""

AC_PASSPHRASE_LEN = 36
AC_PASSPHRASE_WORD_LEN = 4
AC_PASSPHRASE_NUM_WORDS = 9
AC_PASSPHRASE_NUM_BLOCKS = 3
AC_PASSPHRASE_FORMAT = "Passphrase-Format: numeric9x4"
AC_PASSPHRASE_BEGIN_LEN = 2
AC_PASSPHRASE_BEGIN = "Passphrase-Begin: "

PYAC_HOME = os.path.join(os.path.expanduser("~"), '.pyac')
ACCOUNT_ATTRS = ["addr", "pr", "sk", "pk"]
ACCOUNTS_PATH = os.path.join(PYAC_HOME, 'accounts.json')
PEERS_PATH = os.path.join(PYAC_HOME, 'peers.json')
PROFILE_PATH = os.path.join(PYAC_HOME, 'profile.json')
INITIALDATA = os.path.join(BASE_DIR, 'data', 'intial_data.json')
