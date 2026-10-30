#!/usr/bin/env ruby
# Integrates the SoftEther core (libSECore + prefixed OpenSSL) into the Xcode projects.
require 'xcodeproj'

ROOT = File.expand_path('..', __dir__)        # SRP-VPN-Connect/

# ---- 1) Core/SRPCore.xcodeproj: add SRPSoftEtherClient sources ----
core_proj_path = File.join(ROOT, 'Core/SRPCore.xcodeproj')
proj = Xcodeproj::Project.open(core_proj_path)
core_target = proj.targets.find { |t| t.name == 'SRPCore' } or abort 'SRPCore target not found'
group = proj.main_group.find_subpath('SRPCore', false) rescue nil
group ||= proj.main_group
%w[SRPSoftEtherClient.h SRPSoftEtherClient.m].each do |fname|
  next if group.files.any? { |f| f.display_name == fname }
  ref = group.new_file(File.join(ROOT, 'Core/SRPCore', fname))
  if fname.end_with?('.m')
    core_target.source_build_phase.add_file_reference(ref)
  else
    core_target.headers_build_phase.add_file_reference(ref) if core_target.respond_to?(:headers_build_phase) && core_target.headers_build_phase
  end
end
core_target.build_configurations.each do |c|
  hsp = c.build_settings['HEADER_SEARCH_PATHS'] || ['$(inherited)']
  hsp = [hsp] unless hsp.is_a?(Array)
  add = '$(SRCROOT)/../SoftEther/bridge'
  c.build_settings['HEADER_SEARCH_PATHS'] = hsp unless hsp.include?(add)
  hsp << add unless hsp.include?(add)
  c.build_settings['HEADER_SEARCH_PATHS'] = hsp
end
proj.save
puts 'SRPCore project updated'

# ---- 2) main project: link SE libs into extension + mac test target ----
main_proj_path = File.join(ROOT, 'SRP-VPN-Connect.xcodeproj')
proj = Xcodeproj::Project.open(main_proj_path)

lib_paths = [
  '$(SRCROOT)/SoftEther/build/$(EFFECTIVE_PLATFORM_NAME)',
  '$(SRCROOT)/SoftEther/openssl/$(EFFECTIVE_PLATFORM_NAME)/lib',
]
ldflags = ['-lSECore', '-lsrpse_ssl', '-lsrpse_crypto']

%w[SRPTunnel SRP-VPN-ConnectTestsMac].each do |tname|
  t = proj.targets.find { |x| x.name == tname } or abort "#{tname} not found"
  t.build_configurations.each do |c|
    lsp = c.build_settings['LIBRARY_SEARCH_PATHS'] || ['$(inherited)']
    lsp = [lsp] unless lsp.is_a?(Array)
    lib_paths.each { |p| lsp << p unless lsp.include?(p) }
    c.build_settings['LIBRARY_SEARCH_PATHS'] = lsp

    olf = c.build_settings['OTHER_LDFLAGS'] || ['$(inherited)']
    olf = [olf] unless olf.is_a?(Array)
    ldflags.each { |f| olf << f unless olf.include?(f) }
    c.build_settings['OTHER_LDFLAGS'] = olf
  end
  # Security.framework (SecTrust in SRPSoftEtherClient)
  fw_phase = t.frameworks_build_phase
  unless fw_phase.files.any? { |f| f.display_name == 'Security.framework' }
    fw = proj.frameworks_group.new_file('System/Library/Frameworks/Security.framework')
    fw.source_tree = 'SDKROOT'
    fw_phase.add_file_reference(fw)
  end
  puts "#{tname} updated"
end
proj.save
puts 'main project updated'
