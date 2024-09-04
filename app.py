import requests

from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
from dataclasses import dataclass

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from flask_jwt_extended import (
    create_access_token,
    current_user,
    jwt_required,
    JWTManager,
)

from helpers import success, error

from flask_cors import CORS

from slugify import slugify

app = Flask(__name__)


# region sqlalchemy
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


@dataclass
class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str]


@dataclass
class PodcastInfo(db.Model):
    id: Mapped[str] = mapped_column(primary_key=True, index=True)
    title: Mapped[str]
    desc: Mapped[str]
    logo: Mapped[str]
    website: Mapped[str]


@dataclass
class Episode(db.Model):
    id: Mapped[str] = mapped_column(primary_key=True, index=True)
    title: Mapped[str]
    content: Mapped[str]
    logo: Mapped[str]
    player_url: Mapped[str]
    publish_time: Mapped[int]
    duration: Mapped[int]
    episode_number: Mapped[str]
    permalink: Mapped[str]


# configure the NeonDB database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://rew_admin_owner:bWlqraV9Ls3D@ep-calm-sound-a5e2zc0r.us-east-2.aws.neon.tech/rew_admin?sslmode=require"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# initialize the app with the extension
db.init_app(app)

with app.app_context():
    db.create_all()
# endregion

# region jwt
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "030c9d0d-0158-4de9-a50a-8cb7df06a32e"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
jwt = JWTManager(app)


# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user["id"]


# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


# endregion

# region CORS
CORS(app, resources={r"/*": {"origins": "*"}})
# endregion

# region Upload
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "heic", "heif", "tif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# endregion


@app.route("/register", methods=["POST"])
def register():
    data = request.json

    username = data.get("username")
    password = data.get("password")
    confirmation = data.get("confirm")

    # Ensure username was submitted
    if not username:
        return error("Must provide username", 400)

    # Ensure password was submitted
    if not password:
        return error("Must provide password", 400)

    # Ensure confirmation password was submitted
    if not confirmation:
        return error("Must provide confirmation password", 400)

    # Ensure password and confirmation password are matched
    if confirmation != password:
        return error("Passwords do not match", 400)

    # Query database for username
    rows = db.session.execute(select(User).where(User.username == username)).all()

    # Ensure username does not exists
    if len(rows) == 1:
        return error("Username already exist", 400)

    # Register user
    user = User(
        username=username,
        password=generate_password_hash(password, method="pbkdf2")
    )
    db.session.add(user)
    db.session.commit()

    return success("Registered successfully")


@app.route("/login", methods=["POST"])
def login():
    payload = request.json

    username = payload.get("username")
    password = payload.get("password")

    # Ensure username was submitted
    if not username:
        return error("Must provide username", 400)

    # Ensure password was submitted
    elif not password:
        return error("Must provide password", 400)

    # Query database for username
    rows = db.session.execute(select(User).where(User.username == username)).all()

    # Get user information
    userInfo = rows[0].User.__dict__ if len(rows) else None

    # Ensure username exists and password is correct
    if not userInfo or not check_password_hash(userInfo["password"], password):
        return error("Invalid username and/or password", 400)

    access_token = create_access_token(identity={"id": userInfo["id"]})

    # Redirect user to home page
    return success(
        "Logged in successfully",
        {"username": userInfo["username"], "token": access_token},
    )


@app.route("/changePassword", methods=["POST"])
@jwt_required()
def change_password():
    data = request.json

    currentPassword = data.get("currentPassword")
    newPassword = data.get("newPassword")
    confirmation = data.get("confirm")

    # Ensure username was submitted
    if not currentPassword:
        return error("Must provide old password", 400)

    # Ensure password was submitted
    if not newPassword:
        return error("Must provide password", 400)

    # Ensure confirmation password was submitted
    if not confirmation:
        return error("Must provide confirmation password", 400)

    # Ensure password and confirmation password are matched
    if confirmation != newPassword:
        return error("Passwords do not match", 400)

    # Query database for user
    rows = db.session.execute(select(User).where(User.id == current_user.id)).all()
    userInfo = rows[0].User.__dict__ if len(rows) else None

    # Ensure current password is correct
    if not check_password_hash(userInfo["password"], currentPassword):
        return error("Incorrect current password", 400)

    # Update user password
    db.session.execute(
        update(User)
        .where(userInfo["id"] == current_user.id)
        .values(password=generate_password_hash(newPassword, method="pbkdf2"))
    )
    db.session.commit()

    return success("Updated successfully")


@app.route("/syncPodbeanData", methods=["GET"])
@jwt_required()
def sync_podbean_data():
    auth = ("890c52f9d202851c9ba76", "6b61edbd548dda391f100")
    data = {"grant_type": "client_credentials"}

    r_token = requests.post(
        "https://api.podbean.com/v1/oauth/token", auth=auth, json=data
    )

    token = r_token.json()["access_token"]

    r_info = requests.get(
        "https://api.podbean.com/v1/podcast", params={"access_token": token}
    )

    info = r_info.json()["podcast"]

    PodcastInfo.query.delete()
    Episode.query.delete()

    db_info = PodcastInfo(
        id=info["id"],
        title=info["title"],
        desc=info["desc"],
        logo=info["logo"],
        website=info["website"],
    )
    db.session.add(db_info)

    r_episodes = requests.get(
        "https://api.podbean.com/v1/episodes",
        params={"access_token": token, "limit": 100},
    )

    db_episodes = r_episodes.json()["episodes"]

    for item in db_episodes:
        ep = Episode(
            id=item["id"],
            title=item["title"],
            content=item["content"],
            logo=item["logo"],
            player_url=item["player_url"],
            publish_time=item["publish_time"],
            duration=item["duration"],
            episode_number=item["episode_number"],
            permalink=slugify(item["title"])
        )
        db.session.add(ep)

    db.session.commit()

    return success("OK")


@app.route("/getPodcastInfo", methods=["GET"])
def read_podcast_info():
    row = PodcastInfo.query.all()[0]

    info = dict(row.__dict__)
    info.pop("_sa_instance_state", None)

    return success("OK", info)


@app.route("/getPodcastEpisodes", methods=["GET"])
def get_podcast_episodes():
    rows = Episode.query.all()

    result = []
    for item in rows:
        ep = dict(item.__dict__)
        ep.pop("_sa_instance_state", None)
        result.append(ep)

    return success("OK", result)


@app.route("/readPodcastEpisode", methods=["GET"])
def read_podcast_episode():
    permalink = request.args.get("permalink")

    row = Episode.query.filter_by(permalink=permalink).first()

    if not row:
        return error("Episode not found", 404)

    ep = dict(row.__dict__)
    ep.pop("_sa_instance_state", None)

    return success("OK", ep)
