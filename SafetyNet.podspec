Pod::Spec.new do |s|
  s.name             = 'SafetyNet'
  s.version          = '1.0.0'
  s.summary          = 'Jailbreak detection, anti-debugging, integrity validation, and secure Keychain storage for iOS — reports threats without auto-reacting.'
  s.homepage         = 'https://github.com/DipakPanchasara/SafetyNet'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Dipak Panchasara' => 'ios.dipak@gmail.com' }
  s.source           = { :git => 'https://github.com/DipakPanchasara/SafetyNet.git', :tag => s.version.to_s }

  s.ios.deployment_target = '14.0'
  s.swift_version         = '5.9'

  # Mirrors Package.swift's two-target split: the Swift sources do
  # `import SafetyNetObjC`, which requires a distinct Clang module. A single
  # podspec (or subspecs of one podspec) compiles everything into one module
  # and breaks that import, so the ObjC bridge ships as its own sibling pod
  # instead — see SafetyNetObjC.podspec.
  s.dependency 'SafetyNetObjC', s.version.to_s

  s.source_files = 'Sources/SafetyNet/**/*.swift'

  s.frameworks = 'Security', 'UIKit'
end
