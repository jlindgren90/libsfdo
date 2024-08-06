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
]

foreach template : tests
  name = template['name']
  test(
    name,
    executable(
      name,
      name + '.c',
      include_directories: include_dir,
      dependencies: template['deps'],
    )
  )
endforeach

