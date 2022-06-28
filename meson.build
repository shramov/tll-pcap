project('tll-pcap', 'cpp', version: '0.0.0', default_options: ['cpp_std=c++17', 'werror=true', 'optimization=2'])

include = [include_directories('src')]

tll = dependency('tll')
fmt = dependency('fmt')
pcap = dependency('pcap')

lib = shared_library('tll-pcap',
	['src/channel.cc'],
	include_directories : include,
	dependencies : [fmt, pcap, tll],
	install : true,
)

test('pytest', import('python').find_installation('python3')
	, args: ['-m', 'pytest', '-v', '--log-level=DEBUG', 'tests/']
	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
	, workdir: meson.current_source_dir()
)
