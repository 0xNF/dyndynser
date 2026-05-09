This file deals with how to package dyndynser for various platforms

# Debian 13+
Use the `debian:sid` container to package cleanly:
Note that the container should be started from the parent directory of the Git repository, not inside it. The --volume parameter will loop-mount the current directory inside the container. Thus all files created and modified are on the host system, and will persist after the container shuts down.
```bash
cd ..
`podman run --interactive --tty --rm --shm-size=1G --cap-add SYS_PTRACE --env='DEB*' --volume=$PWD:/tmp/test --workdir=/tmp/test debian:sid bash
```

Once inside the container:
```bash
apt update -q && apt install -q --yes git-buildpackage dpkg-dev dh-make
```

Then run:
```bash
dh_make --packagename dyndynser_1.0.1 --single --createorig
```