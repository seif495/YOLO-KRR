import pexpect
import os
import logging
import re # Import the regular expression module

# Configure basic logging - this will still be configured,
# but individual log calls will be conditional.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SnepsApiError(Exception):
    """Custom exception class for SNePS API errors."""
    pass

class SnepsProcessError(SnepsApiError):
    """Raised when there's an error interacting with the SNePS process."""
    pass

class SnepsSyntaxError(SnepsApiError):
    """Raised for SNePS syntax errors."""
    pass

class SnepsInitializationError(SnepsApiError):
    """Raised when SNePS initialization fails."""
    pass

class sneps_api:
    def __init__(self, directory="Sneps-Linux-Exe-2.7.0", enable_logging=True):
        self.current_directory = os.getcwd()
        self.sneps_directory = directory
        self.process = None
        self.logging_enabled = enable_logging
        # Regex to remove "wff<number>!: " prefix
        self.wff_prefix_regex = re.compile(r"wff\d+!:\s*")


        if self.logging_enabled:
            logging.info(f"Logging is enabled for sneps_api instance.")
        else:
            pass # Logging calls will be skipped if not enabled


        # Validate SNePS directory early
        if not os.path.isdir(self.sneps_directory):
            if self.logging_enabled:
                logging.error(f"SNePS directory not found: {self.sneps_directory}")
            raise SnepsInitializationError(f"SNePS directory not found: {self.sneps_directory}")
        if not os.access(os.path.join(self.sneps_directory, "Sneps-2.7.0.sh"), os.X_OK):
            if self.logging_enabled:
                logging.error(f"Sneps-2.7.0.sh not found or not executable in {self.sneps_directory}")
            raise SnepsInitializationError(f"Sneps-2.7.0.sh not found or not executable in {self.sneps_directory}")

    def init(self):
        original_dir = os.getcwd()
        try:
            os.chdir(self.sneps_directory)
            if self.logging_enabled:
                logging.info(f"Changed directory to {self.sneps_directory}")

            # Spawn the SNePS process
            self.process = pexpect.spawn("rlwrap sh Sneps-2.7.0.sh")
            if self.logging_enabled:
                logging.info("SNePS process spawned.")

            # Initial commands and expectations
            self.process.expect("Type")
            if self.logging_enabled:
                logging.info("Initial SNePS prompt 'Type' received.")
            self.process.sendline("(snepslog)")
            self.process.expect("Welcome")
            if self.logging_enabled:
                logging.info("SNePSLOG started, 'Welcome' received.")
            self.process.sendline("clearkb") # Initial clear kb
            self.process.expect("CPU")
            if self.logging_enabled:
                logging.info("Knowledge base cleared during init, 'CPU' prompt received.")

        except pexpect.exceptions.TIMEOUT as e:
            if self.logging_enabled:
                logging.error(f"Timeout during SNePS initialization: {e}")
            self._safe_terminate_process()
            raise SnepsInitializationError(f"Timeout during SNePS initialization: {e}")
        except pexpect.exceptions.EOF as e:
            if self.logging_enabled:
                logging.error(f"SNePS process ended unexpectedly during initialization: {e}")
                before_eof = self.process.before.decode('utf-8', errors='ignore') if self.process and self.process.before else "N/A"
                logging.error(f"Output before EOF: {before_eof}")
            self._safe_terminate_process()
            raise SnepsInitializationError(f"SNePS process ended unexpectedly: {e}. Output: {before_eof if 'before_eof' in locals() else 'N/A'}")
        except OSError as e:
            if self.logging_enabled:
                logging.error(f"OS error during SNePS initialization: {e}")
            self._safe_terminate_process()
            raise SnepsInitializationError(f"OS error: {e}")
        except Exception as e:
            if self.logging_enabled:
                logging.error(f"An unexpected error occurred during SNePS initialization: {e}")
            self._safe_terminate_process()
            raise SnepsInitializationError(f"Unexpected error: {e}")
        finally:
            os.chdir(original_dir)
            if self.logging_enabled:
                logging.info(f"Changed directory back to {original_dir}")


    def _ensure_process_is_alive(self):
        """Checks if the SNePS process is alive."""
        if self.process is None or not self.process.isalive():
            if self.logging_enabled:
                logging.error("SNePS process is not running or not initialized.")
            raise SnepsProcessError("SNePS process is not running. Please call init() first.")

    def clear_kb(self):
        """Sends the 'clearkb' command to SNePS."""
        self._ensure_process_is_alive()
        operation_name = "clear_kb"
        try:
            self.process.sendline("clearkb")
            self.process.expect("CPU") # Expect the CPU prompt after clearkb
            if self.logging_enabled:
                logging.info("Knowledge base cleared successfully via clear_kb().")
            return True
        except pexpect.exceptions.TIMEOUT as e:
            if self.logging_enabled:
                logging.error(f"Timeout during {operation_name} operation: {e}")
            raise SnepsProcessError(f"Timeout during {operation_name}: {e}")
        except pexpect.exceptions.EOF as e:
            if self.logging_enabled:
                logging.error(f"SNePS process ended unexpectedly during {operation_name}: {e}")
            before_eof = self.process.before.decode('utf-8', errors='ignore') if self.process and self.process.before else "N/A"
            raise SnepsProcessError(f"SNePS process ended unexpectedly during {operation_name}. Output: {before_eof}")
        except Exception as e:
            if self.logging_enabled:
                logging.error(f"An unexpected error occurred during {operation_name}: {e}")
            raise SnepsProcessError(f"Unexpected error during {operation_name}: {e}")
        return False


    def inform(self, message):
        self._ensure_process_is_alive()
        operation_name = "inform"
        context_message = f"message '{message}'"
        if not isinstance(message, str) or not message.strip():
            if self.logging_enabled:
                logging.warning("Inform message is empty or not a string.")
            raise ValueError("Inform message cannot be empty.")

        try:
            self.process.sendline(f"{message.strip()}.")
            response = self.process.expect(["CPU", "Error"])

            if response == 0: # Success ("CPU" matched)
                if self.logging_enabled:
                    logging.info(f"Successfully informed: {message}")
                return True
            elif response == 1: # SNePS reported an error ("Error" matched)
                error_details = self.process.before.decode("utf-8", errors='ignore').strip()
                if self.logging_enabled:
                    logging.warning(f"SNePS syntax error for {context_message}. Details: {error_details}")
                self.process.sendline("(continue)")
                self.process.expect("CPU")
                raise SnepsSyntaxError(f"SNePS Error: Incorrect Syntax! SNePS output: {error_details}")

        except pexpect.exceptions.TIMEOUT as e:
            if self.logging_enabled:
                logging.error(f"Timeout during {operation_name} operation for {context_message}: {e}")
            raise SnepsProcessError(f"Timeout during {operation_name}: {e}")
        except pexpect.exceptions.EOF as e:
            if self.logging_enabled:
                logging.error(f"SNePS process ended unexpectedly during {operation_name} for {context_message}: {e}")
            before_eof = self.process.before.decode('utf-8', errors='ignore') if self.process and self.process.before else "N/A"
            raise SnepsProcessError(f"SNePS process ended unexpectedly during {operation_name}. Output: {before_eof}")
        except Exception as e:
            if self.logging_enabled:
                logging.error(f"An unexpected error occurred during {operation_name} for {context_message}: {e}")
            if isinstance(e, SnepsSyntaxError):
                raise 
            raise SnepsProcessError(f"Unexpected error during {operation_name}: {e}")
        return False


    def list_wffs(self):
        self._ensure_process_is_alive()
        operation_name = "list_wffs"
        try:
            self.process.sendline("list-wffs")
            self.process.expect("CPU")
            output = self.process.before.decode("utf-8", errors='ignore')
            
            result = []
            for line in output.splitlines():
                stripped_line = line.strip()
                if ("wff" in stripped_line.lower()) and ("!" in stripped_line):
                    cleaned_line = self.wff_prefix_regex.sub("", stripped_line)
                    result.append(cleaned_line)
            if self.logging_enabled:
                logging.info(f"{operation_name} returned {len(result)} items.")
            return result

        except pexpect.exceptions.TIMEOUT as e:
            if self.logging_enabled:
                logging.error(f"Timeout during {operation_name} operation: {e}")
            raise SnepsProcessError(f"Timeout during {operation_name}: {e}")
        except pexpect.exceptions.EOF as e:
            if self.logging_enabled:
                logging.error(f"SNePS process ended unexpectedly during {operation_name}: {e}")
            before_eof = self.process.before.decode('utf-8', errors='ignore') if self.process and self.process.before else "N/A"
            raise SnepsProcessError(f"SNePS process ended unexpectedly during {operation_name}. Output: {before_eof}")
        except Exception as e:
            if self.logging_enabled:
                logging.error(f"An unexpected error occurred during {operation_name}: {e}")
            raise SnepsProcessError(f"Unexpected error during {operation_name}: {e}")

    def ask(self, message):
        self._ensure_process_is_alive()
        operation_name = "ask"
        context_message = f"query '{message}'"
        if not isinstance(message, str) or not message.strip():
            if self.logging_enabled:
                logging.warning("Ask message is empty or not a string. Returning empty list.")
            return []

        try:
            self.process.sendline(f"ask({message.strip()}).")
            response = self.process.expect(["CPU", "Error"])

            if response == 0: # Success ("CPU" matched)
                output = self.process.before.decode("utf-8", errors='ignore')
                result = []
                for line in output.splitlines():
                    stripped_line = line.strip()
                    if ("wff" in stripped_line.lower()) and ("!" in stripped_line):
                        cleaned_line = self.wff_prefix_regex.sub("", stripped_line)
                        result.append(cleaned_line)
                if self.logging_enabled:
                    logging.info(f"{operation_name} query '{message}' returned {len(result)} items.")
                return result
            elif response == 1: # SNePS reported an error ("Error" matched)
                error_details = self.process.before.decode("utf-8", errors='ignore').strip()
                if self.logging_enabled:
                    logging.warning(f"SNePS syntax error for {context_message}. Details: {error_details}")
                self.process.sendline("(continue)")
                self.process.expect("CPU")
                raise SnepsSyntaxError(f"SNePS Error: Incorrect Syntax for {context_message}! SNePS output: {error_details}")
            
        except pexpect.exceptions.TIMEOUT as e:
            if self.logging_enabled:
                logging.error(f"Timeout during {operation_name} operation for {context_message}: {e}")
            raise SnepsProcessError(f"Timeout during {operation_name}: {e}")
        except pexpect.exceptions.EOF as e:
            if self.logging_enabled:
                logging.error(f"SNePS process ended unexpectedly during {operation_name} for {context_message}: {e}")
            before_eof = self.process.before.decode('utf-8', errors='ignore') if self.process and self.process.before else "N/A"
            raise SnepsProcessError(f"SNePS process ended unexpectedly during {operation_name}. Output: {before_eof}")
        except Exception as e:
            if self.logging_enabled:
                logging.error(f"An unexpected error occurred during {operation_name} for {context_message}: {e}")
            if isinstance(e, SnepsSyntaxError):
                raise 
            raise SnepsProcessError(f"Unexpected error during {operation_name}: {e}")
        return [] 

    def _safe_terminate_process(self):
        """Safely terminates the SNePS process if it's running."""
        if self.process and self.process.isalive():
            try:
                self.process.terminate(force=True)
                if self.logging_enabled:
                    logging.info("SNePS process terminated.")
            except Exception as e:
                if self.logging_enabled:
                    logging.warning(f"Error while terminating SNePS process: {e}")
        self.process = None


    def terminate(self):
        if self.logging_enabled:
            logging.info("Terminating SNePS API session.")
        self._safe_terminate_process()
        original_dir_to_return_to = self.current_directory
        try:
            if os.getcwd() != original_dir_to_return_to:
                os.chdir(original_dir_to_return_to)
                if self.logging_enabled:
                    logging.info(f"Changed directory back to {original_dir_to_return_to}.")
        except OSError as e:
            if self.logging_enabled:
                logging.error(f"Could not change directory back to {original_dir_to_return_to}: {e}")
        finally:
            self.current_directory = os.getcwd()
