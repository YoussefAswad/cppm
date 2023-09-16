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


def get_state(state_path: Path) -> dict:
    main_logger = logging.getLogger("main_logger")
    files = [x for x in state_path.glob("*")]
    state = {}
    MONITORS = {}
    for file in files:
        if file.is_file() and file.name != "log" and file.name != "current_profile":
            if (
                "width" not in file.name
                and "height" not in file.name
                and "refresh" not in file.name
            ):
                with open(file, "r") as f:
                    state[file.name] = f.read().strip()
                main_logger.debug(f"Loaded {file.name} from {file}")

    for file in files:
        if file.is_file() and "width" in file.name:
            monitor_name = file.name.split("_")[0]
            monitor_path = str(state_path / monitor_name)
            with open(f"{monitor_path}_width", "r") as f:
                width = f.read().strip()
            with open(f"{monitor_path}_height", "r") as f:
                height = f.read().strip()
            with open(f"{monitor_path}_refresh", "r") as f:
                refresh = f.read().strip()
            MONITORS[monitor_name] = {
                "WIDTH": int(width),
                "HEIGHT": int(height),
                "REFRESH_RATE": float(refresh) if "." in refresh else int(refresh),
            }

    if len(MONITORS.keys()) > 0:
        state["MONITORS"] = MONITORS
    main_logger.debug(f"Loaded state: {state}")
    return state


def match_wlr_perf( monitor_name: str, rate: int | float) -> str | None:
    # get the available modes
    # output
    wlr_out = (
        os.popen("wlr-randr --output eDP-1 | grep preferred").read().strip().split("\n")
    )
    available_modes = []
    for line in wlr_out:
        col = line.strip().split(" ")
        width, height = col[0].split("x")
        refresh = col[2]
        available_modes.append((width, height, float(refresh)))

    for mode in available_modes:
        if int(mode[2]) == int(rate):
            return mode[2]


def delete_state(state_path: Path):
    main_logger = logging.getLogger("main_logger")
    files = state_path.glob("*")
    for f in files:
        if f.is_file() and f.name != "log":
            try:
                f.unlink()
                main_logger.debug(f"Deleted {f.name}")
            except FileNotFoundError:
                main_logger.warning(f"{f.name} not found")


def merge_dict(dict_1, dict_2):
    merged = {}
    for key in list(dict_1.keys()) + list(dict_2.keys()):
        if key in dict_1 and key in dict_2:
            merged[key] = dict_1[key] | dict_2[key]
        elif key in dict_1:
            merged[key] = dict_1[key]
        else:
            merged[key] = dict_2[key]
    return merged


def save_state(
    state_path: Path,
    SESSION_TYPE: str,
    DESKTOP_ENVIRONMENT: str,
    MONITORS: dict,
    retrieve: dict,
    force: bool = False,
    current_profile: str | None = None,
):
    main_logger = logging.getLogger("main_logger")
    if force:
        delete_state(state_path)

    try:
        os.mkdir(state_path)
        main_logger.debug(f"Created {state_path}")
    except FileExistsError:
        pass

    for monitor_name in MONITORS:
        main_logger.debug(f"Saving {monitor_name}")
        if SESSION_TYPE == "wayland":
            if DESKTOP_ENVIRONMENT == "gnome":
                # TODO: implement gnome save (gnome-randr)
                ...
            elif DESKTOP_ENVIRONMENT == "kde":
                # TODO: implement kde save (kscreen)
                ...
            else:
                command = (
                    f"wlr-randr --output {monitor_name} "
                    + "| grep current"
                    + ' | awk \'{{split($1, arr, "x"); print arr[1] "\\n" arr[2] "\\n" int($3)}}\''
                )
                main_logger.debug(f"Executing {command}")
                output = os.popen(command).read().strip().split("\n")
                main_logger.debug(f"Output: {output}")
                if len(output) != 3:
                    main_logger.error(
                        f"""Output of {command} is not complete:
                            {output}"""
                    )
                    exit(1)
                width, height, refresh = output
                try:
                    with open(state_path / f"{monitor_name}_width", "x") as f:
                        f.write(width)
                except FileExistsError:
                    main_logger.debug(f"{monitor_name} width already exists")
                try:
                    with open(state_path / f"{monitor_name}_height", "x") as f:
                        f.write(height)
                except FileExistsError:
                    main_logger.debug(f"{monitor_name} height already exists")
                try:
                    with open(state_path / f"{monitor_name}_refresh", "x") as f:
                        f.write(refresh)
                except FileExistsError:
                    main_logger.debug(f"{monitor_name} refresh already exists")

        elif SESSION_TYPE == "xorg":
            # TODO: implement xorg save (xrandr)
            ...

    for key in retrieve:
        command = retrieve[key]
        output = os.popen(command).read().strip()
        # check if the output is more than one line
        if "\n" in output:
            main_logger.error(
                f"""Output of {command} is more than one line:
                    {output}"""
            )
            exit(1)
        try:
            with open(state_path / key, "x") as f:
                f.write(output)

            main_logger.debug(f"Saved {key} to {state_path / key}")
        except FileExistsError:
            main_logger.debug(f"{key} already exists")
    if current_profile:
        with open(state_path / "current_profile", "w") as f:
            f.write(current_profile)
    else:
        main_logger.warning("No profile provided")


def find_exe(name: str) -> bool:
    return True if find_executable(name) else False


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


def load_config(config_path: Path, script_path: Path) -> Tuple[dict, list]:
    main_logger = logging.getLogger("main_logger")

    with open(script_path / "schema.json", "r") as f:
        schema = json.load(f)
        main_logger.debug("Loaded schema.json")

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


def exception_handler(exc_type, exc_value, exc_traceback):
    file_logger = logging.getLogger("file_logger")
    console_logger = logging.getLogger("console_logger")
    file_logger.critical(
        f"Uncaught exception: {exc_type.__name__}",
        exc_info=(exc_type, exc_value, exc_traceback),
    )
    console_logger.critical(f"{exc_type.__name__}: {str(exc_value)}")


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


def get_current_profile(state_path: Path) -> str | None:
    main_logger = logging.getLogger("main_logger")
    try:
        with open(state_path / "current_profile", "r") as f:
            current_profile = f.read().strip()
            main_logger.debug(
                f"Loaded current profile from {state_path / 'current_profile'}"
            )
            return current_profile
    except FileNotFoundError:
        main_logger.warning(
            f"Current profile not found in {state_path / 'current_profile'}"
        )
        return None


def get_previous_profile(state_path: Path, profiles_order: list) -> str | None:
    main_logger = logging.getLogger("main_logger")
    current_profile = get_current_profile(state_path)
    if current_profile:
        current_profile_index = profiles_order.index(current_profile)
        if current_profile_index == 0:
            next_profile = None
        else:
            next_profile = profiles_order[current_profile_index - 1]
        main_logger.debug(f"Next profile: {next_profile}")
        return next_profile
    else:
        return profiles_order[-1]


def get_next_profile(state_path: Path, profiles_order: list) -> str | None:
    main_logger = logging.getLogger("main_logger")
    current_profile = get_current_profile(state_path)
    if current_profile:
        current_profile_index = profiles_order.index(current_profile)
        if current_profile_index == len(profiles_order) - 1:
            next_profile = None
        else:
            next_profile = profiles_order[current_profile_index + 1]
        main_logger.debug(f"Next profile: {next_profile}")
        return next_profile
    else:
        return profiles_order[0]


def apply_profile(
    profile: dict,
    commands: dict,
    state_path: Path,
    DESKTOP_ENVIRONMENT: str,
    SESSION_TYPE: str,
):
    main_logger = logging.getLogger("main_logger")
    redirect = " > /dev/null 2>&1"
    selected_commands = (
        commands["global"] + commands[DESKTOP_ENVIRONMENT]
        if DESKTOP_ENVIRONMENT in commands
        else commands["global"]
    )
    for command in selected_commands:
        try:
            command_sub = command.format(**profile)
            os.system(command_sub + redirect)
            main_logger.debug(f"Executed {command_sub}")
        except KeyError as e:
            main_logger.error(f"Key {str(e)} not found in profile, skipping {command}")

    for monitor_name, monitor in profile["MONITORS"].items():
        width = monitor["WIDTH"]
        height = monitor["HEIGHT"]
        refresh = monitor["REFRESH_RATE"]
        command = ""
        if SESSION_TYPE == "wayland":
            if DESKTOP_ENVIRONMENT == "gnome":
                # TODO: implement gnome set (gnome-randr)
                ...
            elif DESKTOP_ENVIRONMENT == "plasma":
                # TODO: implement kde set (kscreen)
                ...
            elif DESKTOP_ENVIRONMENT == "hyprland":
                command = f"hyprctl keyword monitor {monitor_name},{width}x{height}@{refresh},0x0,1"
                os.system(command + redirect)
            else:
                refresh = match_wlr_perf(monitor_name=monitor_name,rate=monitor["REFRESH_RATE"])
                command = f"wlr-randr --output {monitor_name} --mode {width}x{height}@{refresh}Hz"
                os.system(command + redirect)
        elif SESSION_TYPE == "xorg":
            # TODO: implement xorg set (xrandr)
            ...
        if command:
            main_logger.debug(f"Executed {command}")
        else:
            main_logger.error(
                f"No command found for {SESSION_TYPE} and {DESKTOP_ENVIRONMENT}"
            )
    current_profile = get_current_profile(state_path)
    apply_out = (
        f"Applied profile {current_profile}" if current_profile else "Restored"
    ) + "\n"
    apply_out += "Monitors:\n"
    for monitor_name, monitor in profile["MONITORS"].items():
        apply_out += f" - {monitor_name}: {monitor['WIDTH']}x{monitor['HEIGHT']}@{monitor['REFRESH_RATE']}\n"
    apply_out += "Other:\n"
    for option in profile:
        if option != "MONITORS" and option != "priority":
            apply_out += f" - {option}: {profile[option]}\n"

    print(apply_out)
    main_logger.debug(apply_out)
    main_logger.debug(f"Profile set to {current_profile}")


def get_profile_data(
    profile_name: str,
    config: dict,
    default: dict,
    state_path: Path,
    SESSION_TYPE: str,
    DESKTOP_ENVIRONMENT: str,
    save: bool = True,
) -> dict:
    main_logger = logging.getLogger("main_logger")
    if profile_name in config["profiles"]:
        profile = default | config["profiles"][profile_name]
        if "MONITORS" in profile and "MONITORS" in default:
            profile["MONITORS"] = merge_dict(default["MONITORS"], profile["MONITORS"])
        if save:
            save_state(
                state_path=state_path,
                SESSION_TYPE=SESSION_TYPE,
                DESKTOP_ENVIRONMENT=DESKTOP_ENVIRONMENT,
                MONITORS=profile["MONITORS"],
                retrieve=config["retrieve_commands"],
                current_profile=profile_name,
            )
        return profile
    else:
        main_logger.error(f"Profile {profile_name} not found in config")
        exit(1)


def restore_profile(state_path: Path, default: dict) -> dict | None:
    main_logger = logging.getLogger("main_logger")
    saved_state = get_state(state_path)
    if saved_state:
        delete_state(state_path)
        profile = default | saved_state
        if "MONITORS" in profile and "MONITORS" in default:
            profile["MONITORS"] = merge_dict(default["MONITORS"], profile["MONITORS"])
        return profile
    else:
        main_logger.error("No saved state found")
        return None


def waybar_output(state_path: Path) -> str:
    main_logger = logging.getLogger("main_logger")
    current_profile = get_current_profile(state_path)
    tooltip = current_profile.capitalize() if current_profile else "No profile set"
    main_logger.debug(f"Current profile: {current_profile}")
    icons = {
        "powersave": "󰾆",
        "balanced": "󰾅",
        "performance": "󰓅",
    }
    json_dict = {
        "text": icons[current_profile] if current_profile else "󰬹 󰫳 󰫳",
        "tooltip": tooltip,
        "class": current_profile if current_profile else "none",
    }
    json_output = json.dumps(json_dict)
    main_logger.debug(f"Waybar output: {json_output}")
    return json_output


def run_post_script(config_path: Path):
    main_logger = logging.getLogger("main_logger")
    script_path = config_path / "scripts"
    for script in script_path.glob("*"):
        main_logger.debug(f"Running {script}")
        os.system(f"{script} > /dev/null 2>&1")


def main():
    script_name = Path(__file__).stem
    script_path = Path(__file__).resolve().parent
    state_path = Path(f"/tmp/{script_name}")
    state_path.mkdir(exist_ok=True)
    init_logging(state_path)
    sys.excepthook = exception_handler
    main_logger = logging.getLogger("main_logger")
    main_logger.debug(f"Starting {script_name}")

    config_path = get_config_path(script_name)
    config, profiles_order = load_config(config_path, script_path)

    default = {}
    if config["default"]:
        default = config["default"]

    parser = argparse.ArgumentParser()

    # Create a mutually exclusive group for the main actions
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument(
        "--set",
        "-s",
        metavar="<profile_name>",
        help="Apply a specific power profile",
    )
    parser.add_argument(
        "--restore",
        "-r",
        nargs="?",
        const="none",
        default=False,
        help="Restore to saved power profile",
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

    args = parser.parse_args()

    DESKTOP_ENVIRONMENT = os.environ.get("XDG_SESSION_DESKTOP")
    if not DESKTOP_ENVIRONMENT:
        main_logger.error("XDG_SESSION_DESKTOP not set")
        exit(1)

    SESSION_TYPE = os.environ.get("XDG_SESSION_TYPE")
    if not SESSION_TYPE:
        main_logger.error("XDG_SESSION_TYPE not set")
        exit(1)

    profile = None
    if args.set:
        profile = get_profile_data(
            args.set, config, default, state_path, SESSION_TYPE, DESKTOP_ENVIRONMENT
        )
    elif args.restore:
        if args.restore == "none":
            profile = restore_profile(state_path, default)
        else:
            delete_state(state_path)
            profile = get_profile_data(
                args.restore,
                config,
                default,
                state_path,
                SESSION_TYPE,
                DESKTOP_ENVIRONMENT,
                save=False,
            )
    elif args.previous:
        previous_profile = get_previous_profile(state_path, profiles_order)
        if previous_profile:
            profile = get_profile_data(
                previous_profile,
                config,
                default,
                state_path,
                SESSION_TYPE,
                DESKTOP_ENVIRONMENT,
            )
        else:
            main_logger.warning("No previous profile found")
            profile = restore_profile(state_path, default)
    elif args.next:
        next_profile = get_next_profile(state_path, profiles_order)
        if next_profile:
            profile = get_profile_data(
                next_profile,
                config,
                default,
                state_path,
                SESSION_TYPE,
                DESKTOP_ENVIRONMENT,
            )
        else:
            main_logger.warning("No next profile found")
            profile = restore_profile(state_path, default)
    elif args.list:
        main_logger.debug("list option selected")
        current_profile = get_current_profile(state_path)
        for profile in config["profiles"]:
            print(
                f"{'*' if profile == current_profile else ' '} {profile.capitalize()}"
            )
        return
    elif args.get:
        current_profile = get_current_profile(state_path)
        if current_profile:
            print(current_profile)
        else:
            print("No profile applied")
    elif args.waybar:
        print(waybar_output(state_path))
        return

    if profile:
        apply_profile(
            state_path=state_path,
            profile=profile,
            commands=config["commands"],
            DESKTOP_ENVIRONMENT=DESKTOP_ENVIRONMENT,
            SESSION_TYPE=SESSION_TYPE,
        )

    run_post_script(config_path)


if __name__ == "__main__":
    try:
        main()
        logging.getLogger("main_logger").debug("Exiting\n")
    except KeyboardInterrupt:
        logging.getLogger("main_logger").error("Keyboard interrupt: Exiting\n")
        exit(1)
