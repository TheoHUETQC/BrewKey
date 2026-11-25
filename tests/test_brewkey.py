
import math
import statistics
import time
import unittest

from core.password_generator import generate_password, CAR, MDP_SIZE


class TestBrewKey(unittest.TestCase):

    """
    Functional tests for the BrewKey password generator.
    """

    # --------------------------------------------------
    # DETERMINISM TESTS
    # --------------------------------------------------

    def test_same_inputs_produce_same_password(self):
        """The same inputs must always produce the same password."""

        result1 = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        result2 = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        self.assertEqual(result1, result2)

    def test_different_identifiers_produce_different_passwords(self):
        """Different identifiers should normally produce different passwords."""

        result1 = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        result2 = generate_password(
            "facebook.com",
            "MyMasterPassword123"
        )

        self.assertNotEqual(result1, result2)

    def test_different_master_passwords_produce_different_passwords(self):
        """Different master passwords should normally produce different passwords."""

        result1 = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        result2 = generate_password(
            "google.com",
            "AnotherMasterPassword456"
        )

        self.assertNotEqual(result1, result2)

    # --------------------------------------------------
    # PASSWORD FORMAT TESTS
    # --------------------------------------------------

    def test_default_password_length(self):
        """The generated password must have the default length."""

        result = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        self.assertEqual(len(result), MDP_SIZE)

    def test_custom_password_lengths(self):
        """The generator must respect different requested lengths."""

        for size in [1, 8, 16, 23, 32, 64]:

            with self.subTest(length=size):

                result = generate_password(
                    "google.com",
                    "MyMasterPassword123",
                    size
                )

                self.assertEqual(len(result), size)

    def test_only_allowed_characters_are_used(self):
        """Every generated character must belong to the defined alphabet."""

        result = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        for character in result:
            self.assertIn(character, CAR)

    def test_result_is_a_string(self):
        """The generated password must be a string."""

        result = generate_password(
            "google.com",
            "MyMasterPassword123"
        )

        self.assertIsInstance(result, str)

    # --------------------------------------------------
    # INPUT VALIDATION TESTS
    # --------------------------------------------------

    def test_empty_identifier_is_rejected(self):
        """An empty identifier must raise a ValueError."""

        with self.assertRaises(ValueError):
            generate_password("", "MyMasterPassword123")

    def test_empty_master_password_is_rejected(self):
        """An empty master password must raise a ValueError."""

        with self.assertRaises(ValueError):
            generate_password("google.com", "")

    def test_invalid_password_lengths_are_rejected(self):
        """Zero, negative, non-integer and boolean lengths must be rejected."""

        invalid_lengths = [0, -1, 2.5, True]

        for size in invalid_lengths:
            
            with self.subTest(length=size):

                with self.assertRaises(ValueError):
                    generate_password(
                        "google.com",
                        "MyMasterPassword123",
                        size
                    )


# --------------------------------------------------
# ENTROPY ANALYSIS
# --------------------------------------------------

def calculate_theoretical_entropy(length):
    """
    Calculate the theoretical maximum entropy of a generated password.

    Assumes that every character is selected independently
    and uniformly from the available alphabet.
    """

    alphabet_size = len(CAR)

    entropy_per_character = math.log2(alphabet_size)

    return entropy_per_character * length


def display_entropy_report():

    print("\n" + "=" * 50)
    print("BREWKEY - THEORETICAL ENTROPY REPORT")
    print("=" * 50)

    print(f"Alphabet size: {len(CAR)} characters")
    print(
        f"Entropy per character: "
        f"{math.log2(len(CAR)):.4f} bits"
    )

    print("\nPassword entropy:")

    for length in [12, 16, 20, 23, 32]:

        entropy = calculate_theoretical_entropy(length)

        print(
            f"{length} characters: "
            f"{entropy:.2f} bits"
        )

    print("\nNote: These values represent theoretical maximum entropy.")
    print("They do not represent the entropy of the master password.")
    print("They assume independent and uniformly distributed characters.")


# --------------------------------------------------
# PERFORMANCE BENCHMARK
# --------------------------------------------------

def run_performance_benchmark(iterations=10):
    """
    Measure the password generation time on the current machine.

    This benchmark measures legitimate application performance.
    It is not a measurement of an attacker's hardware.
    """

    identifier = "google.com"
    master_password = "BenchmarkMasterPassword123"

    durations = []

    print("\n" + "=" * 50)
    print("BREWKEY - PERFORMANCE BENCHMARK")
    print("=" * 50)

    for _ in range(iterations):

        start = time.perf_counter()

        generate_password(
            identifier,
            master_password
        )

        end = time.perf_counter()

        durations.append(end - start)

    average = statistics.mean(durations)
    median = statistics.median(durations)
    minimum = min(durations)
    maximum = max(durations)

    print(f"Number of iterations: {iterations}")
    print(f"Average generation time: {average:.4f} seconds")
    print(f"Median generation time:  {median:.4f} seconds")
    print(f"Minimum generation time: {minimum:.4f} seconds")
    print(f"Maximum generation time: {maximum:.4f} seconds")

    print("\nNote: Results depend on the hardware and system load.")
    print("These measurements should not be interpreted as")
    print("the speed of an attacker's password guessing attempts.")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":

    print("\n" + "=" * 50)
    print("             BREWKEY TEST SUITE")
    print("=" * 50)

    # Run functional tests
    unittest.main(
        argv=["test_brewkey"],
        exit=False
    )

    # Display theoretical entropy
    display_entropy_report()

    # Run performance benchmark
    run_performance_benchmark()
