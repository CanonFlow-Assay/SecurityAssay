# M0 controls

Clean dependency fixture pins Newtonsoft.Json 13.0.4 metadata. Vulnerable
controls use 12.0.1 metadata. Their NuGet content hashes come from SHA-512 of
official flat-container .nupkg bytes downloaded separately during provisioning;
no vulnerable package code is loaded or executed. Source files are synthetic.

M0 scans declared lock bytes and matches declared package identity against the
local DB; it does not prove authenticity of installed package bytes. A lack of
findings against this fixture is a scoped result, never an endorsement.
Secret controls are generated at qualification time, never issued credentials.

The project-reference fixture adds synthetic NuGet `type: Project` metadata to
the clean dependency control. Its purpose is classification against actual Syft
output; it is not a built/restored application. The npm fixture uses primary
registry integrity metadata for is-number 7.0.0 and a synthetic application root.
No npm package is installed or executed.
