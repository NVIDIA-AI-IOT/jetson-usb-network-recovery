# Third-party software and distribution scope

This source-only distribution contains NVIDIA-authored source code, tests, and documentation. It does not bundle third-party source code, interpreters, libraries, executables, or operating-system packages.

The tool uses an independently installed Python interpreter and its standard library. It invokes existing operating-system commands, including Bash, sudo, dpkg-query, ip, systemctl, id, ssh-keygen, and macOS networking utilities. These programs remain separately installed and are governed by their own licenses. The tool also interacts with the installed NVIDIA Jetson Linux USB service; it does not distribute or replace its vendor scripts.

No third-party license texts are included for redistributed components because no such components are bundled in this distribution. Reassess this scope and include applicable upstream licenses and notices before adding or distributing any third-party code or binary components.
