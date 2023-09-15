#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
from distutils.spawn import find_executable
from pathlib import Path
from typing import Tuple

import yaml
from jsonschema import exceptions, validate

# Define the expected structure for the YAML configuration
schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "default": {
            "type": "object",
            "properties": {
                # "RESOLUTION": {"type": "string"},
                "WIDTH": {"type": "integer"},
                "HEIGHT": {"type": "integer"},
                "DISPLAY": {"type": "string"},
                # "STATE_PATH": {"type": "string"},
                "REFRESH_RATE": {"type": "integer"},
            },
            "required": ["WIDTH", "HEIGHT", "DISPLAY", "REFRESH_RATE"],
        },
        "desktop_commands": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {"type": "string"},
        },
        "profiles": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "priority": {"type": "integer"},
                    "POWER_PROFILE": {"type": "string"},
                    "BRIGHTNESS": {"type": "integer"},
                    "REFRESH_RATE": {"type": "integer"},
                },
                "required": ["POWER_PROFILE", "BRIGHTNESS", "REFRESH_RATE"],
            },
        },
    },
    "required": ["default", "desktop_commands", "profiles"],
}


def init_logging(state_path: Path):
    main_logger = logging.getLogger("main_logger")
    main_logger.setLevel(logging.DEBUG)

    file_logger = logging.getLogger("file_logger")
    file_logger.setLevel(logging.DEBUG)

    console_logger = logging.getLogger("console_logger")
    console_logger.setLevel(logging.ERROR)

    # Create a formatter for the file handler
    file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # Create a file handler to log all messages to a file
    file_handler = logging.FileHandler(state_path / "log")
    file_handler.setLevel(logging.DEBUG)  # Adjust the level as needed
    file_handler.setFormatter(file_formatter)

    # Create a console handler to log errors and critical messages to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)  # Adjust the level as needed

    main_logger.addHandler(file_handler)
    main_logger.addHandler(console_handler)

    file_logger.addHandler(file_handler)
    console_logger.addHandler(console_handler)


def find_exe(name: str) -> bool:
    """Check whether `name` is on PATH."""

    return True if find_executable(name) else False


def exception_handler(exc_type, exc_value, exc_traceback):
    file_logger = logging.getLogger("file_logger")
    console_logger = logging.getLogger("console_logger")
    file_logger.critical(
        f"Uncaught exception: {exc_type.__name__}",
        exc_info=(exc_type, exc_value, exc_traceback),
    )
    console_logger.critical(f"{exc_type.__name__}: {str(exc_value)}")


def get_config_path(script_name: str) -> Path:
    main_logger = logging.getLogger("main_logger")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        config_path = Path(xdg_config_home) / script_name
        main_logger.info(
            f"XDG_CONFIG_HOME set, using {str(config_path)} as config path"
        )
    else:
        config_path = Path.home() / ".config" / script_name
        main_logger.warning(
            f"XDG_CONFIG_HOME not set, using {str(config_path)} as config path"
        )
    if not config_path.is_dir():
        main_logger.error(f"Config path {str(config_path)} not found")
        exit(1)
    return config_path


def load_config(config_path: Path) -> Tuple[dict, list]:
    main_logger = logging.getLogger("main_logger")

    # find the config file with extension .yaml, .yml or .json
    found_configs = [
        x
        for x in list(config_path.glob("config.*"))
        if x.suffix in [".yaml", ".yml", ".json"]
    ]

    if len(found_configs) == 1:
        config_file = found_configs[0]
        main_logger.debug(f"Found config file: {str(config_file)}")
        with open(str(config_file), "r") as f:
            config = yaml.safe_load(f)
            try:
                validate(config, schema)
                main_logger.debug(
                    f"Validation successful. The {config_file.suffix.lstrip('.')} file is valid"
                )
            except exceptions.ValidationError as e:
                main_logger.error(
                    f"Validation failed. {config_file.suffix.lstrip('.')} The  file is not valid"
                )
            except Exception as e:
                main_logger.error(f"An error occurred during validation: {str(e)}")
            # config["default"]["STATE_PATH"] = Path(config["default"]["STATE_PATH"])
        return config, calulate_order(config["profiles"])
    elif len(found_configs) > 1:
        main_logger.error("More than one config file found")
        exit(1)
    else:
        main_logger.error("No config file not found")
        exit(1)


def calulate_order(profiles: dict) -> list:
    main_logger = logging.getLogger("main_logger")
    # calculate the order of the profiles based on the priority
    order = []
    for profile in profiles:
        if "priority" in profiles[profile]:
            order.append((profile, profiles[profile]["priority"]))
        else:
            order.append((profile, 0))
    order.sort(key=lambda x: x[1])
    if len(order) == 0:
        main_logger.warning("No profiles found, cycling will not work")
    return [x[0] for x in order]


def delete_state(state_path: Path):
    main_logger = logging.getLogger("main_logger")
    files = ["brightness", "power_profile", "current_profile"]
    for file in files:
        try:
            (state_path / file).unlink()
            main_logger.debug(f"Deleted {file} file")
        except FileNotFoundError:
            main_logger.debug(f"{file} file not found")


def load_state(state_path: Path) -> dict:
    main_logger = logging.getLogger("main_logger")
    try:
        with open(state_path / "brightness", "r") as f:
            brightness = f.read().strip()
    except FileNotFoundError:
        main_logger.warning("Brightness file not found")
        brightness = None
    try:
        with open(state_path / "power_profile", "r") as f:
            power_profile = f.read().strip()
    except FileNotFoundError:
        main_logger.warning("Power Profile file not found")
        power_profile = None
    try:
        with open(state_path / "current_profile", "r") as f:
            current_profile = f.read().strip()
    except FileNotFoundError:
        main_logger.warning("Current Profile file not found")
        current_profile = None
    return {
        "POWER_PROFILE": power_profile,
        "BRIGHTNESS": brightness,
        "PROFILE": current_profile,
    }


def save_state(state_path: Path, force: bool = False, profile: str = ""):
    main_logger = logging.getLogger("main_logger")
    if force:
        delete_state(state_path)
    power_profile = os.popen("powerprofilesctl get").read().strip()
    brightness = (
        os.popen("brightnessctl -m | awk -F, '{print $4}'").read().strip().strip("%")
    )
    try:
        os.mkdir(state_path)
    except FileExistsError:
        pass
    try:
        with open(state_path / "brightness", "x") as f:
            f.write(brightness)
    except FileExistsError:
        main_logger.info("Brightness already saved")
    try:
        with open(state_path / "power_profile", "x") as f:
            f.write(power_profile)
    except FileExistsError:
        main_logger.info("Power Profile already saved")
    if profile:
        with open(state_path / "current_profile", "w") as f:
            f.write(profile)
    else:
        main_logger.warning("No profile provided")


def apply_profile(
    desktop_session,
    profile: dict,
    state_path: Path,
    # current_profile: str,
    default: dict,
    desktop_commands: dict,
):
    main_logger = logging.getLogger("main_logger")
    is_wayland = True if os.environ.get("XDG_SESSION_TYPE") == "wayland" else False
    # redirect output to /dev/null to avoid cluttering the terminal
    redirect = " > /dev/null 2>&1"
    if is_wayland:
        command = (
            desktop_commands[desktop_session].format(**(default | profile)) + redirect
        )
    else:
        command = (
            "xrandr --output {DISPLAY} --mode {WIDTH}x{HEIGHT} --rate {REFRESH_RATE}".format(
                **(default | profile)
            )
            + redirect
        )

    os.system(command)
    if not find_exe(command.split()[0]):
        main_logger.error(f"Command failed: {command}")
        exit(1)
    main_logger.debug(f"Command executed: {command}")

    command = "powerprofilesctl set {}".format(profile["POWER_PROFILE"]) + redirect
    if not find_exe(command.split()[0]):
        main_logger.error(f"Command failed: {command}")
        exit(1)
    os.system(command)
    main_logger.debug(f"Command executed: {command}")

    command = "brightnessctl set {}%".format(profile["BRIGHTNESS"]) + redirect
    if not find_exe(command.split()[0]):
        main_logger.error(f"Command failed: {command}")
        exit(1)
    os.system(command)
    main_logger.debug(f"Command executed: {command}")

    current_profile = get_current_profile(state_path)
    print(
        f"""{current_profile.capitalize() if current_profile else 'No profile set'}:
    - Brightness: {profile["BRIGHTNESS"]}%
    - Power profile: {profile["POWER_PROFILE"]}
    - Refresh rate: {(default |profile)['REFRESH_RATE']}Hz
    """
    )
    main_logger.debug(f"Profile set to {current_profile}")


def get_current_profile(state_path: Path) -> str | None:
    main_logger = logging.getLogger("main_logger")
    profile = load_state(state_path)
    if profile["PROFILE"]:
        main_logger.debug(f"Current profile: {profile['PROFILE']}")
        return profile["PROFILE"]
    else:
        main_logger.debug("No profile set")
        return None


def waybar_output(state_path: Path) -> str:
    main_logger = logging.getLogger("main_logger")
    profile = load_state(state_path)
    current_profile = profile["PROFILE"] if profile["PROFILE"] else "default"
    tooltip = (
        current_profile.capitalize()
        if current_profile != "default"
        else "No profile set"
    )
    main_logger.debug(f"Current profile: {current_profile}")
    icons = {
        "powersave": "󰾆",
        "balanced": "󰾅",
        "performance": "󰓅",
    }
    json_dict = {
        "text": icons[profile["PROFILE"]] if profile["PROFILE"] else "󰬹 󰫳 󰫳",
        "tooltip": tooltip,
        "class": current_profile,
    }
    json_output = json.dumps(json_dict)
    main_logger.debug(f"Waybar output: {json_output}")
    return json_output


def next_profile(profiles: dict, profiles_order: list, state_path: Path) -> dict:
    profile = load_state(state_path)
    if (
        not profile["POWER_PROFILE"]
        or not profile["BRIGHTNESS"]
        or not profile["PROFILE"]
    ):
        profile_name = profiles_order[0]
        profile = profiles[profile_name]
        save_state(profile=profile_name, state_path=state_path)
    else:
        current_profile = profiles_order.index(profile["PROFILE"])
        if current_profile != len(profiles_order) - 1:
            next_profile = profiles_order[current_profile + 1]
            profile = profiles[next_profile]
            save_state(profile=next_profile, state_path=state_path)
        else:
            delete_state(state_path)
    return profile


def previous_profile(profiles: dict, profiles_order: list, state_path: Path) -> dict:
    profile = load_state(state_path)
    if (
        not profile["POWER_PROFILE"]
        or not profile["BRIGHTNESS"]
        or not profile["PROFILE"]
    ):
        profile_name = profiles_order[-1]
        profile = profiles[profile_name]
        save_state(profile=profile_name, state_path=state_path)
    else:
        current_profile = profiles_order.index(profile["PROFILE"])
        if current_profile != 0:
            next_profile = profiles_order[current_profile - 1]
            profile = profiles[next_profile]
            save_state(profile=next_profile, state_path=state_path)
        else:
            delete_state(state_path)
    return profile


def run_post_script(config_path: Path):
    main_logger = logging.getLogger("main_logger")
    script_path = config_path / "scripts"
    for script in script_path.glob("*"):
        main_logger.debug(f"Running {script}")
        os.system(f"{script} > /dev/null 2>&1")


def main():
    # initializations
    script_name = Path(__file__).stem
    state_path = Path(f"/tmp/{script_name}")
    state_path.mkdir(exist_ok=True)
    init_logging(state_path)
    sys.excepthook = exception_handler
    main_logger = logging.getLogger("main_logger")
    main_logger.debug(f"Starting {script_name}")

    config_path = get_config_path(script_name)
    config, profiles_order = load_config(config_path)
    default = config["default"]
    # state_path = default["STATE_PATH"]
    desktop_commands = config["desktop_commands"]
    profiles = config["profiles"]

    # logging.basicConfig(
    #     level=logging.INFO,  # Set the minimum logging level (other options: DEBUG, WARNING, ERROR, CRITICAL)
    #     format="%(asctime)s [%(levelname)s] %(message)s",
    #     handlers=[
    #         logging.FileHandler(f"{default['STATE_PATH']}/log"),  # Log to a file
    #     ],
    # )
    desktop_session = os.environ.get("DESKTOP_SESSION")
    if desktop_session not in desktop_commands:
        print("Desktop session not supported")
        exit(1)

    # parse options powersave, balanced, performance
    parser = argparse.ArgumentParser()

    # Create a mutually exclusive group for the main actions
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument(
        "--set",
        "-s",
        metavar="<profile_name>",
        help="Apply a specific power profile",
    )
    main_group.add_argument(
        "--restore", "-r", action="store_true", help="Restore to saved power profile"
    )
    main_group.add_argument(
        "--previous",
        "-p",
        action="store_true",
        help="Switch to the previous power profile",
    )
    main_group.add_argument(
        "--next", "-n", action="store_true", help="Switch to the next power profile"
    )
    main_group.add_argument(
        "--list", "-l", action="store_true", help="List available power profiles"
    )
    main_group.add_argument(
        "--get", "-g", action="store_true", help="Get current state"
    )
    main_group.add_argument(
        "--waybar", "-w", action="store_true", help="Waybar json output"
    )

    # Create a mutually exclusive group for the secondary actions
    secondary_group = parser.add_mutually_exclusive_group()
    secondary_group.add_argument(
        "--save", "-S", action="store_true", help="Save current state"
    )
    args = parser.parse_args()

    profile = None

    if args.restore:
        main_logger.debug("restore option selected")
        profile = load_state(state_path)
        if not profile["POWER_PROFILE"] or not profile["BRIGHTNESS"]:
            message = "No settings saved, using balanced"
            main_logger.warning(message)
            print(message)
            profile = profiles["balanced"]
        delete_state(state_path)
    elif args.get:
        main_logger.debug("get option selected")
        current_profile = get_current_profile(state_path)
        print(current_profile if current_profile else "No power profile active")
        return
    elif args.waybar:
        main_logger.debug("waybar option selected")
        print(waybar_output(state_path))
        return
    elif args.list:
        main_logger.debug("list option selected")
        current_profile = get_current_profile(state_path)
        for profile in profiles:
            print(
                f"{'*' if profile == current_profile else ' '} {profile.capitalize()}"
            )
        return
    elif args.next:
        main_logger.debug("next option selected")
        profile = next_profile(profiles, profiles_order, state_path)
    elif args.previous:
        main_logger.debug("previous option selected")
        profile = previous_profile(profiles, profiles_order, state_path)
    elif args.set:
        main_logger.debug("profile option selected")
        if args.set not in profiles:
            raise ValueError(f"Profile {args.set} not found")
        profile = profiles[args.set]
        save_state(profile=args.set, state_path=state_path)

    if profile:
        apply_profile(
            desktop_session=desktop_session,
            profile=profile,
            state_path=state_path,
            default=default,
            desktop_commands=desktop_commands,
        )

    if args.save:
        main_logger.debug("save option selected")
        save_state(state_path=state_path, force=True)
    # os.system("pkill -RTMIN+7 waybar")
    run_post_script(config_path)


if __name__ == "__main__":
    try:
        main()
        logging.getLogger("main_logger").debug("Exiting\n")
    except KeyboardInterrupt:
        logging.getLogger("main_logger").error("Keyboard interrupt: Exiting\n")
        exit(1)
