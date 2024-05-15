examples = [
  {
    'name': 'basedir-dump',
    'deps': [
      sfdo_basedir,
    ],
  },
  {
    'name': 'desktop-file-query',
    'deps': [
      sfdo_desktop_file,
    ],
  },
  {
    'name': 'desktop-dump',
    'deps': [
      sfdo_basedir,
      sfdo_desktop,
    ],
  },
  {
    'name': 'desktop-load',
    'deps': [
      sfdo_basedir,
      sfdo_desktop,
    ],
  },
  {
    'name': 'desktop-exec',
    'deps': [
      sfdo_basedir,
      sfdo_desktop,
    ],
  },
  {
    'name': 'icon-lookup',
    'deps': [
      sfdo_basedir,
      sfdo_icon,
    ],
  },
]

foreach template : examples
  name = template['name']
  executable(
    name,
    name + '.c',
    include_directories: include_dir,
    dependencies: template['deps'],
  )
endforeach
