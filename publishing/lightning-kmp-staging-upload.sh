#!/bin/bash -x
#
# first you must sign all files with something like:
# find release -type f -print -exec gpg -ab {} \;
#

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

if [[ -z "${OSS_USER}" ]]; then
  echo "OSS_USER is not defined"
  exit 1
fi

read -p "Password : " -s OSS_PASSWORD

for i in lightning-kmp-core \
		lightning-kmp-core-iosarm64 \
		lightning-kmp-core-iossimulatorarm64 \
		lightning-kmp-core-iosx64 \
		lightning-kmp-core-jvm \
		lightning-kmp-core-linuxx64 \
		lightning-kmp-core-macosarm64 \
		lightning-kmp-core-macosx64
do
	pushd .
	cd release/fr/acinq/lightning/$i/$VERSION &&\
	pwd &&\
	jar -cvf bundle.jar *&&\
	curl -v -XPOST -u $OSS_USER:$OSS_PASSWORD --upload-file bundle.jar https://oss.sonatype.org/service/local/staging/bundle_upload	
  popd
done
