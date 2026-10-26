% === CLASS MEMBERSHIPS ===

member(person, human).

member(bicycle, vehicle).
member(car, vehicle).
member(motorcycle, vehicle).
member(bus, vehicle).
member(train, vehicle).
member(truck, vehicle).

member(dog, animal).
member(cat, animal).
member(horse, animal).
member(cow, animal).
member(sheep, animal).
member(elephant, animal).
member(bear, animal).
member(zebra, animal).
member(giraffe, animal).

member(fire_hydrant, obstacle).
member(stop_sign, obstacle).
member(bench, obstacle).
member(traffic_light, obstacle).
member(parking_meter, obstacle).

% === DANGER RULES ===

dangerous(X) :- left(X, Y), member(X, human), (member(Y, vehicle); member(Y, animal); member(Y, obstacle)).

dangerous(X) :- right(X, Y), member(X, human), (member(Y, vehicle); member(Y, animal); member(Y, obstacle)).

dangerous(X) :- above(X, Y), member(X, human), (member(Y, vehicle); member(Y, animal); member(Y, obstacle)).

dangerous(X) :- below(X, Y), member(X, human), (member(Y, vehicle); member(Y, animal); member(Y, obstacle)).

dangerous(X) :- in-front-of(X, Y), member(X, human), (member(Y, vehicle); member(Y, animal)).
