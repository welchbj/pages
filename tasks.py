"""Tasks for management of this project."""

from __future__ import print_function

import markdown2
import os
import shutil
import sys

from collections import (
    namedtuple)
from jinja2 import (
    Environment,
    FileSystemLoader)
from pathlib import (
    Path)


HERE = os.path.dirname(os.path.abspath(__file__))
MD_DIR = os.path.join(HERE, 'markdown')
STATIC_DIR = os.path.join(HERE, 'static')
JINJA_DIR = os.path.join(HERE, 'jinja')
BUILD_DIR = os.path.join(HERE, 'build')
BUILD_STATIC_DIR = os.path.join(BUILD_DIR, 'static')

MD_EXTRAS = ['fenced-code-blocks', 'header-ids', 'metadata', 'tables']

Page = namedtuple(
    'Page',
    ['published_at', 'last_modified_at', 'title', 'raw_html'])


def _mkdir_if_not_present(dirname):
    """Utility to make a directory if it does not already exist."""
    Path(dirname).mkdir(parents=True, exist_ok=True)


def _rmdir_if_present(dirname):
    """Delete a directory if it is present."""
    try:
        shutil.rmtree(dirname)
    except FileNotFoundError:
        pass


def _iter_paths(directory, glob_pattern):
    """Iterate over files within a directory that match a pattern."""
    for path in Path(directory).glob(glob_pattern):
        yield path


def build():
    """Compile the site into the build directory."""
    clean()
    _mkdir_if_not_present(BUILD_DIR)

    # compile html pages
    env = Environment(loader=FileSystemLoader(JINJA_DIR))
    for html_path in _iter_paths(JINJA_DIR, '*.html'):
        template = env.get_template(html_path.name)
        rendered_page = template.render()
        dest_path = os.path.join(BUILD_DIR, html_path.name)
        with open(dest_path, 'w') as f:
            f.write(rendered_page)
    print('[*] Compiled HTML pages into', BUILD_DIR)

    # compile markdown pages
    md_template = env.get_template('md_page.template')
    for md_path in _iter_paths(MD_DIR, '*.md'):
        with md_path.open(encoding='utf-8') as f:
            md_source = f.read()

        md_as_html = markdown2.markdown(md_source, extras=MD_EXTRAS)
        page = Page(
            md_as_html.metadata['published_at'],
            md_as_html.metadata['last_modified_at'],
            md_as_html.metadata['title'],
            str(md_as_html))
        rendered_page = md_template.render(page=page)

        dest_fname = md_path.stem + '.html'
        dest_path = os.path.join(BUILD_DIR, dest_fname)
        with open(dest_path, 'w') as f:
            f.write(rendered_page)
    print('[*] Compiled markdown pages into', BUILD_DIR)

    # copy static files into the build static directory
    _rmdir_if_present(BUILD_STATIC_DIR)
    shutil.copytree(STATIC_DIR, BUILD_STATIC_DIR)
    print('[*] Copied static assets into', BUILD_STATIC_DIR)


def clean():
    """Remove the build directory."""
    _rmdir_if_present(BUILD_DIR)
    print('[*] Cleaning done')


def serve():
    """Run a livereload server on port 5000."""
    from livereload import Server

    watch_patterns = [
        os.path.join(MD_DIR, '*.md'),
        os.path.join(JINJA_DIR, '*'),
        os.path.join(STATIC_DIR, '*'),
        os.path.join(STATIC_DIR, '**', '*')
    ]

    server = Server()
    build()
    for pattern in watch_patterns:
        server.watch(pattern, build)

    print('[*] Running livereload server on port 5000')
    server.serve(root=BUILD_DIR, port=5000, host='127.0.0.1')


TASKS = {
    'build': build,
    'clean': clean,
    'serve': serve
}
TASK_KEYS = list(sorted(TASKS.keys()))


if __name__ == '__main__':
    sys.argv.pop(0)
    if len(sys.argv) != 1:
        print('Must specify task to perform', file=sys.stderr)
        sys.exit(1)

    task = sys.argv.pop()
    if task not in TASK_KEYS:
        print('Specified task must be one of:', ', '.join(TASK_KEYS))
        sys.exit(1)

    task_func = TASKS[task]
    task_func()
