import os
import re

def split_csharp_file(input_file, output_dir="output"):
    """Split C# file into individual class files with namespace directories."""
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Read the input file
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    
    # Extract using statements
    using_statements = []
    namespace = None
    
    for line in lines:
        if line.strip().startswith('using '):
            using_statements.append(line)
        elif line.strip().startswith('namespace '):
            # Extract just the namespace name
            namespace_match = re.search(r'namespace\s+([a-zA-Z_][a-zA-Z0-9_.]*)', line.strip())
            if namespace_match:
                namespace = namespace_match.group(1)
    
    # Find classes, interfaces, structs, enums
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for class/interface/struct/enum declarations
        match = re.search(r'(public|private|internal|protected)?\s*(static|abstract|sealed)?\s*(class|interface|struct|enum)\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
        
        if match:
            block_type = match.group(3)
            block_name = match.group(4)
            start_line = i
            
            # Find matching closing brace
            brace_count = 0
            found_opening = False
            end_line = start_line
            
            for j in range(start_line, len(lines)):
                for char in lines[j]:
                    if char == '{':
                        brace_count += 1
                        found_opening = True
                    elif char == '}':
                        brace_count -= 1
                
                if found_opening and brace_count == 0:
                    end_line = j
                    break
            
            # Create namespace directory structure
            namespace_dir = output_dir
            if namespace:
                # Convert namespace to directory path (e.g., "MyApp.Services" -> "MyApp/Services")
                namespace_path = namespace.replace('.', os.path.sep)
                namespace_dir = os.path.join(output_dir, namespace_path)
                os.makedirs(namespace_dir, exist_ok=True)
            
            # Create the file content
            file_content = []
            
            # Add using statements
            file_content.extend(using_statements)
            if using_statements:
                file_content.append("")
            
            # Add namespace if exists
            if namespace:
                file_content.append(f"namespace {namespace}")
                file_content.append("{")
            
            # Add the class/interface/struct/enum
            block_lines = lines[start_line:end_line + 1]
            if namespace:
                # Indent the content
                for line in block_lines:
                    file_content.append("    " + line if line.strip() else line)
            else:
                file_content.extend(block_lines)
            
            # Close namespace
            if namespace:
                file_content.append("}")
            
            # Write to file in appropriate directory
            filename = f"{block_name}.cs"
            filepath = os.path.join(namespace_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(file_content))
            
            print(f"Created: {filepath}")
            
            i = end_line + 1
        else:
            i += 1

# Usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <input_file.cs> [output_directory]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
    
    print(f"Splitting {input_file} into {output_dir}/")
    split_csharp_file(input_file, output_dir)
    print("Done!")