#!/bin/bash

# Fix common syntax errors in API route files

echo "Fixing malformed API route files..."

# Fix files with malformed try blocks
find src/app/api -name "*.ts" -type f | while read file; do
    echo "Processing $file..."
    
    # Fix malformed try blocks missing {
    sed -i 's/try\s*$/try {/g' "$file"
    
    # Fix malformed catch blocks missing } or {
    sed -i 's/catch\s*$/} catch (error) {/g' "$file"
    sed -i 's/catch (error)\s*$/} catch (error) {/g' "$file"
    
    # Fix files ending without proper closing braces
    if [[ $(tail -1 "$file") != "}" ]]; then
        if [[ $(tail -1 "$file") == "  }" ]]; then
            echo "}" >> "$file"
        fi
    fi
    
    # Remove merge conflict markers
    sed -i '/^<<<<<<< HEAD$/d' "$file"
    sed -i '/^=======$/d' "$file"
    sed -i '/^>>>>>>> /d' "$file"
    
    # Fix incomplete function declarations
    sed -i 's/function\s*$/function handler() {/g' "$file"
    
done

echo "API route files fixed."