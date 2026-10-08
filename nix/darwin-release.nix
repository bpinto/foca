# The release the macOS package installs (nix/darwin.nix). The release
# workflow updates it on main after it publishes a vX.Y.Z release; the tagged
# commit itself can't hold the hash of an archive built from it. tip is
# never pinned: its assets change with every commit. A hash of null means no
# release is pinned yet.
{
  version = "0.1.0";
  hash = null;
}
