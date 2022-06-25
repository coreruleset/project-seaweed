# type: ignore
import nox
import tempfile

nox.options.sessions = "lint", "tests", "safety", "mypy"
locations = ["src", "tests", "noxfile.py"]
python_versions = ["3.9.13"]


def install_with_constraints(
    session: nox.options.sessions, *args: str, **kwargs: str
) -> None:
    with tempfile.NamedTemporaryFile() as requirements:
        session.run(
            "poetry",
            "export",
            "--dev",
            "--format=requirements.txt",
            "--without-hashes",
            f"--output={requirements.name}",
            external=True,
        )
        session.install(f"--constraint={requirements.name}", *args, **kwargs)


@nox.session(python=python_versions)
def tests(session: nox.options.sessions) -> None:
    args = session.posargs or ["--cov", "-m", "not e2e"]
    session.run("poetry", "install", "--no-dev", external=True)
    install_with_constraints(
        session, "coverage[toml]", "pytest", "pytest-cov", "pytest-mock"
    )
    session.run("pytest", *args)


@nox.session(python=python_versions)
def black(session: nox.options.sessions) -> None:
    args = session.posargs or locations
    install_with_constraints(session, "black")
    session.run("black", *args)


@nox.session(python=python_versions)
def lint(session: nox.options.sessions) -> None:
    args = session.posargs or locations
    install_with_constraints(
        session,
        "flake8",
        "flake8-bandit",
        "flake8-black",
        "flake8-bugbear",
        "flake8-annotations",
    )
    session.run("flake8", *args)


@nox.session(python=python_versions)
def safety(session: nox.options.sessions) -> None:
    with tempfile.NamedTemporaryFile() as requirements:
        session.run(
            "poetry",
            "export",
            "--dev",
            "--format=requirements.txt",
            "--without-hashes",
            f"--output={requirements.name}",
            external=True,
        )
        install_with_constraints(session, "safety")
        session.run("safety", "check", f"--file={requirements.name}", "--full-report")

@nox.session(python=python_versions)
def mypy(session: nox.options.sessions) -> None:
    args = session.posargs or locations
    install_with_constraints(session, "mypy")
    session.run("mypy", *args)