#!/bin/bash

if [ $# -eq 0 ]; then
	REZ_WORKING_PATH=`dirname "$0"`
else
	REZ_WORKING_PATH="."
fi

REZ_DEFAULT_SRC=("$REZ_WORKING_PATH"/input/*.brz)
REZ_WORKING_DIR="$REZ_WORKING_PATH/exploded"
REZ_SEARCH_PATH=(`dirname "$0"` "$HOME")
REZ_EXECUTABLES="rezexplode rezpack"

find_rez() {
	for file in $REZ_EXECUTABLES; do
		REZ_PATH=`which "$file"`
		if [ -z "$REZ_PATH" ]; then
			for path in ${REZ_SEARCH_PATH[@]}; do
				for REZ_PATH in `find $path -type f \
					-name "$file"`; do
					if [ -x "$REZ_PATH" ]; then
						break 3
					fi
				done
			done
		fi
	done

	if [ ! -x "$REZ_PATH" ]; then
		echo "Cannot find rezexplode or rezpack."
		exit 1
	fi
}
find_rez

rm -rf "$REZ_WORKING_DIR"

for file in "${@:-${REZ_DEFAULT_SRC[@]}}"; do
	dir=`basename -s .brz "$file"`
	"$REZ_PATH" -x -o "$REZ_WORKING_DIR"/"$dir" "$file"
done

find "$REZ_WORKING_DIR" -type f -exec basename {} \; | sort -f | uniq -d -i \
	| while read dup; do
	find "$REZ_WORKING_DIR" -type f -name "$dup" | sort -f | sed '$d' \
		| xargs -I{} rm {}
done

for dir in "$REZ_WORKING_DIR"/*; do
	file=`basename "$dir".brz`
	"$REZ_PATH" -p -o "$REZ_WORKING_PATH"/"$file" "$dir"/
done

rm -rf "$REZ_WORKING_DIR"
