project(
  'libsfdo',
  'c',
  version: '0.1.0',
  license: 'BSD-2-Clause',
  default_options: [
    'c_std=c11',
    'warning_level=3',
  ],
)

soversion = '0'

cc = meson.get_compiler('c')

add_project_arguments(cc.get_supported_arguments([
  '-Wconversion',
  '-Wendif-labels',
  '-Wimplicit-fallthrough=2',
  '-Wlogical-op',
  '-Wmissing-include-dirs',
  '-Wmissing-prototypes',
  '-Wold-style-definition',
  '-Wpointer-arith',
  '-Woverflow',
  '-Wshadow',
  '-Wstrict-aliasing=2',
  '-Wstrict-prototypes',
  '-Wundef',

  '-fvisibility=hidden',

  '-D_POSIX_C_SOURCE=200809L',
]), language: 'c')

# TODO: drop in favor of a desktop entry format library
inih = subproject(
  'inih',
  default_options: [
    'default_library=static',
    'distro_install=false',
    'with_INIReader=false',

    'multi-line_entries=false',
    'utf-8_bom=false',
    'inline_comments=false',
    'start-of-line_comment_prefix=#',
    'allow_no_value=false',
    'stop_on_first_error=true',
    'report_line_numbers=false',
    'call_handler_on_new_section=true',
    'use_heap=true',
    'max_line_length=65536',
    'initial_malloc_size=1024',
    'allow_realloc=true',
  ],
).get_variable('inih_dep')

include_dir = include_directories('include')

subdir('sfdo')

private_libs = [
  {
    'name': 'grow',
  },
  {
    'name': 'hash',
  },
  {
    'name': 'log',
  },
  {
    'name': 'strbuild',
  },
  {
    'name': 'strpool',
  },
]

foreach template : private_libs
  name = template['name']
  set_variable('private_' + template['name'],
    declare_dependency(
      link_with: static_library(
        'sfdo-private-' + name,
        get_variable('private_' + name + '_src'),
        include_directories: include_dir,
        dependencies: template.get('deps', [])
      ),
    )
  )
endforeach

install_headers('include/sfdo-common.h')

pkgconfig = import('pkgconfig')

libs = [
  {
    'name': 'basedir',
    'description': 'XDG base directory specification implementation in C',
  },
  {
    'name': 'desktop-file',
    'deps': [
      private_grow,
      private_hash,
    ],
    'description': 'Desktop entry file format parser library',
  },
  {
    'name': 'icon',
    'deps': [
      inih,
      private_grow,
      private_hash,
      private_log,
      private_strbuild,
      private_strpool,
    ],
    'sfdo-deps': [
      'basedir',
    ],
    'description': 'Icon theme specification implementation in C',
  },
]

foreach template : libs
  name = template['name']

  subdir('sfdo-' + name)

  install_headers('include/sfdo-' + name + '.h')

  deps = template.get('deps', [])
  foreach sfdo_dep : template.get('sfdo-deps', [])
    deps += get_variable('sfdo_' + sfdo_dep.underscorify())
  endforeach

  lib = library(
    'sfdo-' + name,
    get_variable('sfdo_' + name.underscorify() + '_src'),
    include_directories: include_dir,
    dependencies: deps,
    version: soversion,
    install: true,
  )

  dep = declare_dependency(
    include_directories: include_dir,
    link_with: lib,
  )

  set_variable('sfdo_' + name.underscorify(), dep)

  full_name = 'libsfdo-' + name

  meson.override_dependency(full_name, dep)

  pkgconfig.generate(
    lib,
    name: full_name,
    version: meson.project_version(),
    description: template['description'],
  )
endforeach

#####

if get_option('examples')
  subdir('examples')
endif
