---
title: FIPS-compatible builds of Pinniped binaries
description: Reference for FIPS builds of Pinniped binaries
cascade:
  layout: docs
menu:
  docs:
    name: FIPS-compatible builds
    weight: 30
    parent: reference
---
By default, the Pinniped supervisor and concierge use ciphers that
are not supported by FIPS 140-2 or 140-3. If you are deploying Pinniped in an
environment with FIPS compliance requirements, you will have to build
the binaries yourself.

The open source Pinniped project does not provide official support for FIPS configuration.
We provide this for informational purposes only.

There are two options for building FIPS-compatible server binaries.

## Using Go's GOFIPS140

The top-level [Dockerfile](https://github.com/vmware/pinniped/blob/main/Dockerfile) has a build arg to allow you
to optionally enable GOFIPS140. Before choosing which value to set for this build arg, please refer to the
Go [announcement of GOFIPS140](https://go.dev/blog/fips140) and [documentation for GOFIPS140](https://go.dev/doc/security/fips140).

## The old option: Using boring crypto

The Pinniped team provides an [example Dockerfile](https://github.com/vmware/pinniped/blob/main/hack/Dockerfile_fips)
demonstrating how you can build Pinniped images using boring crypto.

This sample dockerfile uses the `fips_strict` build tag and Golang's `GOEXPERIMENT=boringcrypto` compiler option.

Note that the Go team has announced the deprecation of their support for boring crypto, so this method may
stop working in some future version of Go.

## The build commands

To build the Pinniped container image, first clone and repo and checkout the release tag:
```bash
$ git clone git@github.com:vmware/pinniped.git
$ cd pinniped
$ git checkout {{< latestversion >}}
```

If you choose to use GOFIPS140, then choose the value of GOFIPS140 that you prefer and run:
```bash
# For example, if you prefer to use "certified"...
$ docker build . --build-arg "GOFIPS140=certified"
```

If you choose to use the old boring crypto, then instead run:
```bash
$ docker build -f hack/Dockerfile_fips .
```

Push the image to your preferred container image repository.

Now you can deploy [the concierge]({{< ref "install-concierge" >}}) and [the supervisor]({{< ref "install-supervisor" >}}) 
by specifying this image instead of the standard Pinniped image in your `values.yaml` or `deployment.yaml` file.
