//! Corpus directory traversal for streaming cmin, without holding a file list.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::hash::BuildHasher;
use std::io;
use std::path::{Path, PathBuf};

/// Corpus inputs in `dir` (regular files, or symlinks to them, that `filter` accepts) in
/// `read_dir` order.
pub fn input_paths<F>(dir: &Path, filter: F) -> io::Result<impl Iterator<Item = PathBuf>>
where
    F: Fn(&Path) -> bool,
{
    Ok(fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter_map(move |entry| {
            let path = entry.path();
            let is_file = match entry.file_type() {
                Ok(ft) if ft.is_symlink() => path.is_file(),
                Ok(ft) => ft.is_file(),
                Err(_) => false,
            };
            (is_file && filter(&path)).then_some(path)
        }))
}

/// Number of corpus inputs in `dir`, as [`input_paths`] defines them.
pub fn count_inputs<F>(dir: &Path, filter: F) -> io::Result<usize>
where
    F: Fn(&Path) -> bool,
{
    Ok(input_paths(dir, filter)?.count())
}

/// Deletes every input in `dir` whose file name is not in `keep`; returns how many. Nothing
/// else may write to `dir` meanwhile, or new inputs are deleted unevaluated.
pub fn remove_unselected<F, S>(
    dir: &Path,
    filter: F,
    keep: &HashSet<OsString, S>,
) -> io::Result<usize>
where
    F: Fn(&Path) -> bool,
    S: BuildHasher,
{
    let mut removed = 0;
    for path in input_paths(dir, filter)? {
        let selected = path.file_name().is_some_and(|n| keep.contains(n));
        if !selected && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    // Mirrors the generated `is_corpus_input`: skip dotfiles and metadata sidecars.
    fn not_metadata(path: &Path) -> bool {
        let name = path.file_name().unwrap().to_string_lossy();
        !name.starts_with('.') && !name.ends_with(".metadata") && !name.ends_with(".meta.json")
    }

    fn names_in(dir: &Path) -> BTreeSet<OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect()
    }

    fn keep(names: &[&str]) -> HashSet<OsString> {
        names.iter().map(OsString::from).collect()
    }

    #[test]
    fn counts_only_filtered_regular_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a"), b"1").unwrap();
        fs::write(dir.path().join("b"), b"2").unwrap();
        fs::write(dir.path().join("a.metadata"), b"{}").unwrap();
        fs::write(dir.path().join(".state"), b"").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        assert_eq!(count_inputs(dir.path(), not_metadata).unwrap(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_file_is_input_dangling_is_not() {
        let dir = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        fs::write(target.path().join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(target.path().join("real"), dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(target.path().join("gone"), dir.path().join("dangling"))
            .unwrap();
        std::os::unix::fs::symlink(target.path(), dir.path().join("dirlink")).unwrap();
        let paths: Vec<PathBuf> = input_paths(dir.path(), not_metadata).unwrap().collect();
        assert_eq!(paths, vec![dir.path().join("link")]);
    }

    #[test]
    fn remove_unselected_keeps_selected_sidecars_and_subdirs() {
        let dir = TempDir::new().unwrap();
        for name in ["a", "b", "c", "a.metadata", "b.meta.json", ".state"] {
            fs::write(dir.path().join(name), name).unwrap();
        }
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("inner"), b"x").unwrap();

        let removal = remove_unselected(dir.path(), not_metadata, &keep(&["b"])).unwrap();

        assert_eq!(removal, 2);
        let expected: BTreeSet<OsString> = ["b", "a.metadata", "b.meta.json", ".state", "sub"]
            .iter()
            .map(OsString::from)
            .collect();
        assert_eq!(names_in(dir.path()), expected);
        assert!(dir.path().join("sub").join("inner").exists());
    }
}
