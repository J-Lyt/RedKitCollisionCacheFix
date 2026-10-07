# RedKitCollisionCacheFix
Fixes an issue where the CollisionCache fails to cook when a workspace .redcloth has a valid APEX/APB in its source file, but REDkit's attached in-memory cloth resource has an empty APB.

This fix will Reload that resource, then lets the normal physics ProcessFile load it again.
