#!/bin/bash

# Find all route files with parameter issues and fix them
for file in $(find src/app/api -name "*.ts" -exec grep -l "export async function.*props: { params: Promise" {} \;); do
    echo "Fixing $file"
    
    # Fix syntax issues where the opening brace got misplaced
    sed -i 's/export async function \([A-Z]\+\)(request: NextRequest, props: { params: Promise<[^>]*> })\n  const params = await props\.params; {/export async function \1(request: NextRequest, props: { params: Promise<{ id: string }> }) {\n  const params = await props.params;/g' "$file"
    
    # Fix cases where the brace is on the wrong line
    sed -i ':a;N;$!ba;s/export async function \([A-Z]\+\)(request: NextRequest, props: { params: Promise<[^>]*> })\n  const params = await props\.params; {/export async function \1(request: NextRequest, props: { params: Promise<{ id: string }> }) {\n  const params = await props.params;/g' "$file"
    
    # Handle applicationId parameter case
    sed -i 's/props: { params: Promise<{ applicationId: string }> }/props: { params: Promise<{ applicationId: string }> }/g' "$file"
    
done