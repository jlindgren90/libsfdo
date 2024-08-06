project(
  'libsfdo',
  'c',
  version: '0.1.3',
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

include_dir = include_directories('include')

subdir('common')

private = static_library(
  'sfdo-private',
  private_src,
  include_directories: include_dir,
)

install_headers('include/sfdo-common.h')

pkgconfig = import('pkgconfig')

libs = [
  {
    'name': 'basedir',
    'description': 'XDG base directory specification implementation in C',
  },
  {
    'name': 'desktop-file',
    'description': 'Desktop entry file format parser library',
  },
  {
    'name': 'desktop',
    'sfdo-deps': [
      'basedir',
      'desktop-file',
    ],
    'description': 'Desktop entry specification implementation in C',
  },
  {
    'name': 'icon',
    'sfdo-deps': [
      'basedir',
      'desktop-file',
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
    link_with: private,
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

if get_option('examples')
  subdir('examples')
endif

if get_option('tests')
  subdir('tests')
endif
