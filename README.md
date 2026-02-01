# Disclaimer

This is my personal cmake template, it's mostly vibe-coded and it's made to fit my usecase I'm open to any suggestions to make it better I will be updating it in case I learned more about cmake. 

# Creating a new project

A project can be created using cmake, two starter templates are available `cli` and `gui`.

```sh
cmake -DNAME=<project_name> -P ./cmake/new_project.cmake
```

for GUI which uses `WinMain` instead of the normal `int main()`.

```sh
cmake -DNAME=<project_name> -DGUI=ON -P ./cmake/new_project.cmake
```

The command will create a directory with a starter `main.cpp` file and add the directory to the root `CMakeLists.txt`.

```sh
cmake -DNAME=<project_name> -DSINGLE=ON -P ./cmake/new_project.cmake
```

single mode can be used for singular project folders the root will contain the src of the project.

## Building code

configure the project

```sh
cmake -S . -B build
```

To build all projects.

```sh
cmake --build build 
```

To build a specific project

```sh
cmake --build build --target <project_name>
```

By default the project will be built using Debug config, though it can be configured using --config parameter

```sh
cmake --build build --config Release --target <project_name>
```

You can always omit `project_name` to build all projects.

To run the project you will find the final exe at `build/<project_name>/<config>/` (e.g: `build/getVersion/Release`). 


# References

- [Protensec - Calling ntdll functions directly](https://www.proteansec.com/reverse-engineering/calling-ntdll-functions-directly/)
- [Concealed Code Execution](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection)