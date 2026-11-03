platform :ios, '15.0'
workspace 'SRP-VPN-Connect.xcworkspace'
project 'SRP-VPN-Connect.xcodeproj'

target 'SRP-VPN-Connect' do
  pod 'IQKeyboardManager', '~> 6.5'
  pod 'Toast', '~> 4.0'
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '15.0'
    end
  end
end
