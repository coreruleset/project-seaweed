# type: ignore
import nox

@nox.session(python=["3.9.13"])
def tests(session):
    args = session.posargs or ["--cov"]
    session.run("poetry", "install", external=True)
    session.run("pytest", *args)