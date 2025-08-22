#!/bin/bash

# Define the folder and file extension
folder_path="build"
extension="json"

# Store the full paths of all files with the specified extension in a variable
files=$(find "$folder_path" -type f -name "*.$extension")

# Print the variable to see the paths
echo "$files"
