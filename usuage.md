bash# Split a C# file
python csharp_splitter.py input.cs

# Specify output directory
python csharp_splitter.py input.cs -o my_output_folder

# Process content directly as string
python csharp_splitter.py "your C# code here" -c





pythonfrom csharp_splitter import split_csharp_content

# Your C# code as a string
csharp_code = """
using System;
using System.Collections.Generic;

namespace MyProject
{
    public class User
    {
        public string Name { get; set; }
    }
    
    public interface IRepository
    {
        void Save(object item);
    }
}
"""

# Split into individual files
files = split_csharp_content(csharp_code, "output")


What It Does

Parses your C# code to identify separate classes, interfaces, structs, and enums
Extracts using statements and namespace information
Creates individual .cs files for each code block
Maintains proper formatting and indentation
Preserves namespace structure in each file

The app handles complex scenarios like nested braces, comments, and different access modifiers. Each generated file will be properly formatted and ready to compile.