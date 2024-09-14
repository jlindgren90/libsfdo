tests = [
  {
    'name': 'basedir',
    'deps': [
      sfdo_basedir,
    ],
  },
  {
    'name': 'desktop-file',
    'deps': [
      sfdo_desktop_file,
    ],
  },
  {
    'name': 'desktop',
    'deps': [
      sfdo_desktop,
    ],
    'datadir': 'desktop',
  },
  {
    'name': 'icon',
    'deps': [
      sfdo_icon,
    ],
    'datadir': 'icon',
  },
]

foreach template : tests
  name = template['name']

  deps = []
  if 'datadir' in template
    datadir = template['datadir']
    deps += custom_target(
      name + '-data',
      output: name + '-data',
      command: ['cp', '-R', meson.current_source_dir() / datadir, datadir]
    )
  endif

  test(
    name,
    executable(
      name,
      name + '.c',
      include_directories: include_dir,
      dependencies: template['deps'],
    ),
    depends: deps,
  )
endforeach

