Pod::Spec.new do |s|
    s.name             = 'libzcashlc'
    s.version          = '0.0.1'
    s.summary          = 'Rust core for ZCash clients'
    s.homepage         = 'https://github.com/dh-ecc/libzcashlc'
    s.license          = { :type => 'MIT', :file => 'LICENSE' }
    s.author           = { 
        'Francisco Gindre' => 'francisco.gindre@gmail.com',
        'Jack Grigg' => 'str4d@electriccoin.co'
     }
    s.source           = { :git => 'https://github.com/dh-ecc/libzcashlc', :tag => s.version.to_s }
    s.vendored_frameworks = 'releases/XCFramework/libzcashlc.xcframework'
    s.preserve_paths = 'releases/XCFramework/libzcashlc.xcframework'
    s.static_framework = true
end
