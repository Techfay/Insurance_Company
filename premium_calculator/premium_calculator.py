# def calculate_premium(age, coverage, term):
#     # Example premium calculation logic
#     base_rate = 5  # Base rate per $1000 coverage
#     age_factor = 0.1 * (age - 30)  # Increase 10% for each year over 30
#     term_factor = 0.2 * (term - 1)  # Increase 20% for each additional year

#     premium = (coverage / 1000) * base_rate * (1 + age_factor) * (1 + term_factor)
#     return round(premium, 2)
def calculate_life_premium(age, coverage, term):
    """
    Calculate life insurance premium.
    """
    base_rate = 5
    age_factor = 0.1 * (age - 30) if age > 30 else 0
    term_factor = 0.2 * (term - 1)
    premium = (coverage / 1000) * base_rate * (1 + age_factor) * (1 + term_factor)
    return round(premium, 2)

def calculate_health_premium(age, coverage, pre_existing_conditions=False):
    """
    Calculate health insurance premium.
    """
    base_rate = 7
    age_factor = 0.15 * (age - 25) if age > 25 else 0  # Age penalty starts above 25
    condition_factor = 1.5 if pre_existing_conditions else 1  # Higher premium for pre-existing conditions
    premium = (coverage / 1000) * base_rate * (1 + age_factor) * condition_factor
    return round(premium, 2)
# def calculate_health_premium(age, coverage, pre_existing_conditions=False):
#     """
#     Calculate health insurance premium.
#     """
#     base_rate = 7
#     age_factor = 0.15 * (age - 25) if age > 25 else 0
#     condition_factor = 1.5 if pre_existing_conditions else 1
#     premium = (coverage / 1000) * base_rate * (1 + age_factor) * condition_factor
#     return round(premium, 2)

def calculate_vehicle_premium(vehicle_age, vehicle_value, driver_age):
    """
    Calculate vehicle insurance premium.
    """
    base_rate = 3
    vehicle_age_factor = 0.05 * vehicle_age  # Older vehicles increase premiums
    driver_age_discount = -0.1 if driver_age < 25 else -0.05  # Young drivers have higher discounts
    premium = (vehicle_value / 1000) * base_rate * (1 + vehicle_age_factor + driver_age_discount)
    return round(premium, 2)
# def calculate_vehicle_premium(vehicle_age, vehicle_value, driver_age):
#     """
#     Calculate vehicle insurance premium.
#     """
#     base_rate = 3
#     vehicle_age_factor = 0.05 * vehicle_age
#     driver_age_discount = -0.1 if driver_age < 25 else -0.05
#     premium = (vehicle_value / 1000) * base_rate * (1 + vehicle_age_factor + driver_age_discount)
#     return round(premium, 2)
