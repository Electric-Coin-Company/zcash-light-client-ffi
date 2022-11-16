Pod::Spec.new do |s|
    s.name             = 'libzcashlc'
    s.version          = '0.1.0'
    s.summary          = 'Rust core for Zcash clients'
    s.homepage         = 'https://github.com/zcash-hackworks/zcash-light-client-ffi'
    s.license          = { :type => 'MIT', :file => 'LICENSE' }
    s.author           = { 
        'Francisco Gindre' => 'francisco.gindre@gmail.com',
        'Jack Grigg' => 'str4d@electriccoin.co'
     }
    s.source           = { :git => 'https://github.com/zcash-hackworks/zcash-light-client-ffi.git', :tag => s.version.to_s }
    s.vendored_frameworks = 'releases/XCFramework/libzcashlc.xcframework'
    s.preserve_paths = 'releases/XCFramework/libzcashlc.xcframework'
    s.ios.deployment_target = '12.0'
    s.static_framework = true
end
