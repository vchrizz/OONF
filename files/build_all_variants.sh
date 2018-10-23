#!/bin/bash

# this script checks out the current revision of the oonf.git repository and builds nine variants of the source

function build_oonf {
	echo ""
	echo "build CMAKE_BUILD_TYPE=${1} OONF_LOGGING_LEVEL=${2}"
	mkdir build-${1}-${2}
	cd build-${1}-${2}
	cmake >/dev/null -D CMAKE_BUILD_TYPE:String=${1} -D OONF_LOGGING_LEVEL:String=${2} ..
	make >/dev/null all
	cd ..
}

if [ ! -d "oonf" ]; then
  # Clone git repository
  git clone git://olsr.org/oonf.git
fi

# cleanup source directory
cd oonf
git pull
git checkout master
git reset --hard
git clean -d -f -q

# build all useful variants of OONF
build_oonf Debug debug
build_oonf Debug info
build_oonf Debug warn
build_oonf Release debug
build_oonf Release info
build_oonf Release warn
build_oonf MinSizeRel debug
build_oonf MinSizeRel info
build_oonf MinSizeRel warn
