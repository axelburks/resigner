"""
resigner is an iOS app re-signer
  this module provides functionality for re-signing iOS apps with a new provisioning profile and/or identity. It includes a command-line interface that allows users to specify the target app, the new provisioning profile, the new identity, and any additional entitlements or modifications to the app's Info.plist file.

  Example usage:
    $ python resigner.py /path/to/app.ipa -i <identity> -p <profile> -e <entitlement> -n <name> -s <scheme1> <scheme2> ... -o <output>
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import re
import os
import shutil
import plistlib

import logging

log = logging.getLogger(__name__)

if TYPE_CHECKING:
  from typing import Optional

__version__ = '1.0.0'

class ShellProcess:
  def __init__(self, cmdline: str, cwd: Optional[str] = None, check: bool = False) -> None:
    """
    Initializes a new instance of the ShellProcess class.
    
    :param cmdline: The command line string to execute.
    :type cmdline: str
    :param cwd: The current working directory to execute the command in. Defaults to None.
    :type cwd: Optional[str], optional
    :param check: Whether to raise an exception if the command returns a non-zero exit code. Defaults to False.
    :type check: bool, optional
    """
    self._cmdline = cmdline
    self._cwd = cwd
    self._check = check

  def invoked(self) -> str:
    """
    Executes the command line string and returns the output as a string.
    
    :return: The output of the executed command as a string.
    :rtype: str
    """
    from subprocess import run, PIPE
    return self._as_str(run(self._cmdline, cwd=self._cwd, shell=True, check=self._check, stdout=PIPE).stdout)

  def _as_str(self, x: bytes) -> str:
    """
    Decodes a bytes object to a string using utf-8 encoding.
    
    :param x: The bytes object to be decoded.
    :type x: bytes
    :return: The decoded string.
    :rtype: str
    """
    return x.decode('utf-8')

def resolved_path_of(path: str, mask: str) -> str:
  """
  Resolves the path of a file or directory using a wildcard mask.
  
  :param path: The path to the file or directory.
  :type path: str
  :param mask: The wildcard mask to use for resolving the path.
  :type mask: str
  :return: The resolved path.
  :rtype: str
  """
  from glob import glob
  return glob(os.path.join(path, mask))[0]

def decoded_profile(profile: bytes) -> bytes:
  """
  Extracts the XML portion of a binary iOS provisioning profile.
  
  :param profile: The binary iOS provisioning profile.
  :type profile: bytes
  :return: The XML portion of the provisioning profile.
  :rtype: bytes
  """
  m = re.search(rb'<\?xml version="1.0".*</plist>', profile, flags=re.DOTALL)
  assert m
  return bytes(m.group(0))

def merged_entitlements(profile: bytes, entitlements: Optional[bytes]) -> bytes:
  """
  Merges the entitlements of an iOS provisioning profile with a set of entitlements.
  
  :param profile: The binary iOS provisioning profile.
  :type profile: bytes
  :param entitlements: The entitlements to merge with the provisioning profile. Defaults to None.
  :type entitlements: Optional[bytes], optional
  :return: The merged entitlements.
  :rtype: bytes
  """
  a = plistlib.loads(decoded_profile(profile))['Entitlements']
  if entitlements is not None:
    b = plistlib.loads(entitlements, fmt=plistlib.FMT_XML)
    for k in 'get-task-allow',:
      if k in b:
        log.warn(f'[*] merged_entitilements: dropping entitlement key "{k}"')
        del b[k]
    if '.*' in a['application-identifier']:
      for k in 'aps-environment',:
        if k in b:
          log.warn(f'[*] merged_entitilements: dropping entitlement key "{k}" due to we are signing with wildcard provisioning profile')
          del b[k]
    a.update(b)
  return plistlib.dumps(a)

def modify_info(bundle_path: str, display_name: str = None, schemes: list = None) -> None:
  """
  Modifies the Info.plist file of an iOS app bundle.
  
  :param bundle_path: The path to the iOS app bundle.
  :type bundle_path: str
  :param display_name: The new display name for the app. Defaults to None.
  :type display_name: str, optional
  :param schemes: The new URL schemes for the app. Defaults to None.
  :type schemes: list, optional
  """
  info_paths = [l for l in ShellProcess(f'/usr/bin/find "{bundle_path}" -name "Info.plist" -depth 1 -print0', check=True).invoked().split('\0') if l]
  for info_plist in info_paths:
    if schemes or display_name:
      with open(info_plist, 'rb+') as file:
        plist_data = plistlib.load(file)
        bundle_id = plist_data['CFBundleIdentifier']
        # modify schemes
        if schemes:
          log.info(f'[.] add schemes: {schemes}')
          plist_data['CFBundleURLTypes'] = plist_data['CFBundleURLTypes'] if 'CFBundleURLTypes' in plist_data else []
          plist_data['CFBundleURLTypes'].append({
            "CFBundleTypeRole": "Editor",
            "CFBundleURLName": bundle_id,
            "CFBundleURLSchemes": schemes
          })
        if display_name:
          log.info(f'[.] modify display_name: {display_name}')
          plist_data['CFBundleDisplayName'] = display_name
        # save
        file.seek(0)
        plistlib.dump(plist_data, file)

def replace_files(bundle_path: str, rpsource: list, rpdestination: list) -> None:
  """
  Replaces files in an iOS app bundle with new files from some specified source directories.

  :param bundle_path: The path to the iOS app bundle.
  :type bundle_path: str
  :param rpsource: A list of source file or directory paths to replace.
  :type rpsource: list
  :param rpdestination: A list of destination paths to copy the source files or directories to.
  :type rpdestination: list
  """
  for rps,rpd in zip(rpsource,rpdestination):
    log.info(f'[.] replace files: {rps} -> {rpd}')
    if os.path.isdir(rps):
      shutil.copytree(rps, os.path.join(bundle_path, rpd), dirs_exist_ok=True)
    else:
      shutil.copyfile(rps, os.path.join(bundle_path, rpd))
  
def do_resign(identity: str, provisioning_profile: str, entitlement: Optional[str], 
              target: str, output: str, 
              display_name: Optional[str], schemes: Optional[list], 
              rpsource: Optional[list], rpdestination: Optional[list]) -> None:
  """
  Resigns an iOS app with the given identity, provisioning profile, entitlement, display name, and URL schemes.

  Args:
  - identity (str): The identity to use, typically the fingerprint of the certificate.
  - provisioning_profile (str): The provisioning profile file to use.
  - entitlement (Optional[str], optional): The entitlement to include, if any.
  - target (str): The path to the iOS app to re-sign.
  - output (str): The output filename for the re-signed app.
  - display_name (Optional[str], optional): The new display name for the app, if any.
  - schemes (Optional[list], optional): The new URL schemes for the app, if any.
  - rpsource (Optional[list], optional): Source files or dirs using in replace action.
  - rpdestination (Optional[list], optional): Destination files or dirs using in replace action.
  """
  import shlex
  import tempfile

  # Commenting it out because it adds single quotes to the variable value, causing the shell command to fail.
  # identity = shlex.quote(identity)
  # provisioning_profile = shlex.quote(provisioning_profile)
  target_ori = target
  target = shlex.quote(target)
  output = shlex.quote(output)

  with tempfile.TemporaryDirectory() as t:
    os.chdir(t)
    if target_ori.endswith(".ipa"):
      log.info('[.] extracting ipa')
      ShellProcess(f'unzip -q {target}', check=True).invoked()
    else:
      log.info('[.] coping app')
      ShellProcess(f'mkdir Payload && cp -r {target} Payload', check=True).invoked()
    bundle_path = resolved_path_of('Payload', '*.app')
    
    log.info('[.] manipulating profile and entitlements')
    profiled_paths = [l for l in ShellProcess(f'/usr/bin/find "{bundle_path}" -name "embedded.mobileprovision" -print0', check=True).invoked().split('\0') if l]
    if profiled_paths:
      for l in profiled_paths:
        shutil.copyfile(provisioning_profile, l)
    else:
      shutil.copyfile(provisioning_profile, os.path.join(bundle_path, 'embedded.mobileprovision'))
    if entitlement is not None:
      shutil.copyfile(entitlement, os.path.join(bundle_path, 'ent.xcent'))
      
    # modify info
    if schemes or display_name:
      modify_info(bundle_path, display_name=display_name, schemes=schemes)
      
    # replace files
    if rpsource and rpdestination:
      replace_files(bundle_path, rpsource=rpsource, rpdestination=rpdestination)
    
    with tempfile.NamedTemporaryFile() as tf:
      try:
        ent = open(resolved_path_of(bundle_path, '*.xcent'), 'rb').read()
      except IndexError:
        ent = None
      tf.write(merged_entitlements(open(provisioning_profile, 'rb').read(), ent))
      tf.flush()

      log.info('[.] replacing signatures')
      ShellProcess(r'/usr/bin/find -E "{}" -depth -regex "^.*\.(app|appex|framework|dylib|car)" -print0 | xargs -0 codesign -vvvvf -s "{}" --deep --entitlements {}'.format(bundle_path, identity, tf.name), check=True).invoked()

    log.info(f'[.] generating ipa: {output}')
    ShellProcess('rm -f {target} && zip -qr {target} *'.format(target=output), check=True).invoked()

def entry() -> None:
  """
  entry is the entry point for the resigner command-line interface.
  """
  from argparse import ArgumentParser

  logging.basicConfig(level=logging.INFO, format='%(message)s')

  parser = ArgumentParser(description='iOS app resigner.')
  parser.add_argument('target')
  parser.add_argument('-o', '--output', help='Output filename')
  parser.add_argument('-i', '--identity', required=True, help='Identity to use, typically fingerprint of the certificate')
  parser.add_argument('-p', '--profile', required=True, help='Provisioning profile file to use')
  parser.add_argument('-e', '--entitlement', help='Entitlement to include, if any')
  parser.add_argument('-n', '--name', help='Modify app display name, if any')
  parser.add_argument('-s', '--schemes', nargs='+', help='Add app url schemes to info.plist, if any')
  parser.add_argument('-rps', '--rpsource', nargs='+', help='Source files or dirs using in replace action')
  parser.add_argument('-rpd', '--rpdestination', nargs='+', help='Destination files or dirs using in replace action')
  args = parser.parse_args()

  if not args.output:
    args.output = re.sub(r'(\.(ipa|app))$', r'-resigned.ipa', args.target, flags=re.IGNORECASE)

  if not args.entitlement:
    log.info(f'[+] resigning {args.target} with profile {args.profile} and identity {args.identity}')
  else:
    log.info(f'[+] resigning {args.target} with profile {args.profile} and identity {args.identity}, including entitlements {args.entitlement}')

  do_resign(
    identity=args.identity,
    provisioning_profile=os.path.realpath(args.profile),
    entitlement=os.path.realpath(args.entitlement) if args.entitlement else None,
    target=os.path.realpath(args.target),
    output=os.path.realpath(args.output),
    display_name=args.name,
    schemes=args.schemes,
    rpsource=args.rpsource,
    rpdestination=args.rpdestination,
  )

  log.info('[+] done')

if __name__ == '__main__':
  entry()