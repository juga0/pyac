Running
=========

An updated command line usage description can be obtained with:

    autocrypt -h

At the time of writing the output is:

    usage: autocrypt [-h] [--version] [-d] [-m PGPHOME] [-l] [-n NEWACCOUNT]
                 [-r NEWPEER] [-a] [-g] [-u] [-p PASSPHRASE] [-c] [-f FROMH]
                 [-t TO] [-s SUBJECT] [-b BODY] [-e PE] [-i INPUT] [-o OUTPUT]

    optional arguments:
      -h, --help            show this help message and exit
      --version             show program's version number and exit
      -d, --debug           Set logging level to debug
      -m PGPHOME, --pgphome PGPHOME
                            Path to Autocrypt home, ~/.pyac by default
      -l, --list            List account and peers
      -n NEWACCOUNT, --newaccount NEWACCOUNT
                            Email address for the new account. It will also
                            generate new OpenPGP keys.
      -r NEWPEER, --newpeer NEWPEER
                            Email address for the new peer.
      -a, --genac           Generate Autocrypt Email. Use -f, -t, -s, -b, or the
                            defaults will be use
      -g, --genag           Generate Autocrypt Gossip Email
      -u, --genas           Generate Autocrypt Setup Email
      -p PASSPHRASE, --passphrase PASSPHRASE
                            Passphrase to generate an Autocrypt Setup Email
      -c, --genasc          Generate Autocrypt Setup Code
      -f FROMH, --fromh FROMH
                            Email sender address and OpenPGP UID
      -t TO, --to TO        Email recipient addresses separatade by comma
      -s SUBJECT, --subject SUBJECT
                            Subject for the Autocrypt Email
      -b BODY, --body BODY  Body for the Autocrypt Email
      -e PE, --pe PE        prefer-encrypt for the Autocrypt Email
      -i INPUT, --input INPUT
                            Path to the Email to parse, by default:
                            /home/user/_my/code/mailencrypt-
                            related/pyac/tests/data/example-simple-autocrypt-
                            pyac.eml
      -o OUTPUT, --output OUTPUT
                            Path to store the Autocrypt Email, by default:
                            /tmp/output.eml

An useful argument when reporting bugs is ``-d``.
