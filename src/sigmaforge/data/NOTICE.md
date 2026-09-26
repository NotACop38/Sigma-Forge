# Third-party data notices

`attack.json` and `atlas.json` are pinned snapshots of technique and tactic
identifiers, names, and technique-to-tactic mappings, extracted by
`scripts/update_taxonomy.py`. sigma-forge uses them offline to validate rule
tags and to render coverage reports.

## MITRE ATT&CK® (`attack.json`)

Source: MITRE ATT&CK Enterprise, retrieved from MITRE's official TAXII 2.1
server (`attack-taxii.mitre.org`). The snapshot records its ATT&CK version.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation.

License: The MITRE Corporation (MITRE) hereby grants you a non-exclusive,
royalty-free license to use ATT&CK® for research, development, and commercial
purposes. Any copy you make for such purposes is authorized provided that you
reproduce MITRE's copyright designation and this license in any such copy.

Terms of use and disclaimers: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

## MITRE ATLAS™ (`atlas.json`)

Source: the MITRE ATLAS data release published at
`atlas.mitre.org/atlas-data`. The snapshot records its release (for example
`2026.09`). The snapshot is a derived subset: identifiers, names, and tactic
mappings only.

Copyright The MITRE Corporation. Licensed under the Apache License, Version
2.0; see `LICENSE-APACHE-2.0.txt` in this directory. Distributed on an "AS IS"
basis, without warranties or conditions of any kind.

ATT&CK® is a registered trademark and ATLAS™ is a trademark of The MITRE
Corporation.
