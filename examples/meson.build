examples = [
  {
    'name': 'basedir-dump',
    'deps': [
      sfdo_basedir,
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
