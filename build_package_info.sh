#!/bin/bash

# Ensure we are in a Git repository
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a Git repository"; exit 1; }

# Process stable branches
git branch -r | grep -E 'origin/[3-9]+\.[0-9]+-stable$' | sed 's/origin\///' | while read -r branch; do
    echo "Checking out branch: $branch"
    git checkout --force "$branch" || { echo "Failed to checkout $branch"; continue; }
    python3 get_package_info.py "$branch"
done

# Process tags
git tag | grep -E '^v[3-9]\.[0-9]+\.[0-9]+$' | sort -V | while read -r tag; do
    filename="output/${tag}_packages.json"
    # Check if the file already exists
    if [ ! -f "$filename" ]; then
        echo "Checking out tag: $tag"
        git checkout --force "$tag" || { echo "Failed to checkout $tag"; continue; }
        
        python3 get_package_info.py "$tag"
    else
        echo "Skipping $tag, file $filename already exists."
    fi

done


