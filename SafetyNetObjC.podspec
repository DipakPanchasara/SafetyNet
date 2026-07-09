Pod::Spec.new do |s|
  s.name             = 'SafetyNetObjC'
  s.version          = '2.1.0'
  s.summary          = 'Objective-C bridge target for the SafetyNet pod. Not intended for standalone use.'
  s.homepage         = 'https://github.com/DipakPanchasara/SafetyNet'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Dipak Panchasara' => 'panchasara.dipak@gmail.com' }
  s.source           = { :git => 'https://github.com/DipakPanchasara/SafetyNet.git', :tag => s.version.to_s }

  s.ios.deployment_target = '14.0'

  s.source_files         = 'Sources/SafetyNetObjC/**/*.{h,m}'
  s.public_header_files  = 'Sources/SafetyNetObjC/include/*.h'
end
